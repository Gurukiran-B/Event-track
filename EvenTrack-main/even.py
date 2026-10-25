from flask import Flask, request, jsonify, render_template, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.api_core.exceptions import AlreadyExists
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

secret_key = os.environ.get('SECRET_KEY')
if not secret_key or len(secret_key) < 32:
    raise RuntimeError("SECRET_KEY must be configured with at least 32 characters.")
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
)
try:
    trusted_proxy_count = int(os.environ.get('TRUSTED_PROXY_COUNT', '0'))
except ValueError as exc:
    raise RuntimeError("TRUSTED_PROXY_COUNT must be a non-negative integer.") from exc
if trusted_proxy_count < 0:
    raise RuntimeError("TRUSTED_PROXY_COUNT must be a non-negative integer.")
if trusted_proxy_count:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=trusted_proxy_count)
rate_limit_storage_uri = os.environ.get('RATELIMIT_STORAGE_URI')
if not rate_limit_storage_uri:
    raise RuntimeError("RATELIMIT_STORAGE_URI must be configured.")

# Restrict CORS to localhost in development. Set ALLOWED_ORIGIN env var in production.
_allowed_origin = os.environ.get('ALLOWED_ORIGIN', 'http://localhost:5000')
CORS(app, origins=[_allowed_origin], supports_credentials=True)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=rate_limit_storage_uri,
    headers_enabled=True
)

# Application Timezone: Asia/Kolkata (IST = UTC + 5:30)
IST = timezone(timedelta(hours=5, minutes=30))

# ----------------------------
# Firebase Setup & Initialization
# ----------------------------
db = None


def init_firebase(cred_path=None, client=None):
    """
    Explicitly initialize Firebase Firestore client.

    Parameters:
        cred_path (str, optional): Path to the Firebase service account JSON.
            Defaults to FIREBASE_CREDENTIALS_PATH env var, GOOGLE_APPLICATION_CREDENTIALS env var,
            or 'firebase-service-account-key.json' in the same directory as even.py.
        client (firestore.Client, optional): Pre-configured or mock Firestore client
            for dependency injection during testing.

    Returns:
        firestore.Client: Initialized Firestore client.

    Raises:
        FileNotFoundError: If the credential file does not exist.
        ValueError: If the credential file is malformed or Firebase initialization fails.
    """
    global db
    if client is not None:
        db = client
        return db

    target_path = cred_path or os.environ.get('FIREBASE_CREDENTIALS_PATH') or \
                  os.environ.get('GOOGLE_APPLICATION_CREDENTIALS') or \
                  os.path.join(os.path.dirname(__file__), 'firebase-service-account-key.json')

    if not os.path.exists(target_path):
        raise FileNotFoundError(
            f"Firebase service account credentials not found at '{target_path}'. "
            "Please provide a valid service account JSON file or set the "
            "FIREBASE_CREDENTIALS_PATH environment variable."
        )

    try:
        cred = credentials.Certificate(target_path)
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        db = firestore.client()
        return db
    except Exception as e:
        raise ValueError(
            f"Failed to initialize Firebase using credentials at '{target_path}': {e}"
        ) from e


@app.before_request
def _ensure_db_initialized():
    """
    Ensure the Firestore client is initialized before servicing any request.
    In production (e.g. under WSGI), initializes on first request if not already done.
    If credentials are missing or invalid, raises a clear error rather than failing unpredictably.
    """
    global db
    if db is None:
        try:
            init_firebase()
        except Exception as e:
            app.logger.error("Database initialization failed: %s", e)
            return jsonify({
                'success': False,
                'error': 'Database service unavailable'
            }), 500

# ----------------------------
# Auth helpers
# ----------------------------

def require_admin_session(f):
    """Decorator: reject request with 401 if no valid admin session cookie."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return jsonify({'success': False, 'error': 'Unauthorized: Admin access required'}), 401
        if session.get('admin_account_source') == 'users':
            try:
                account = db.collection('users').document(session.get('admin_account_id')).get()
                if not account.exists or account.to_dict().get('role') != 'admin' \
                        or account.to_dict().get('status', 'active') != 'active':
                    session.clear()
                    return jsonify({'success': False, 'error': 'Unauthorized: Admin account is inactive'}), 401
            except Exception as e:
                app.logger.error("admin session validation failed: %s", e)
                return jsonify({'success': False, 'error': 'Authentication service unavailable'}), 500
        return f(*args, **kwargs)
    return decorated


def require_user_session(f):
    """Decorator: reject request with 401 if neither user nor admin session exists."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_logged_in') and not session.get('admin_logged_in'):
            return jsonify({'success': False, 'error': 'Unauthorized: Login required'}), 401
        return f(*args, **kwargs)
    return decorated


def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': csrf_token}


@app.before_request
def _validate_csrf_token():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return None
    token = session.get('_csrf_token')
    provided_token = request.headers.get('X-CSRF-Token', '')
    if not token or not hmac.compare_digest(token, provided_token):
        return jsonify({'success': False, 'error': 'CSRF validation failed'}), 403
    return None


@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'success': False, 'error': 'Too many requests. Please try again later.'}), 429


def _stable_document_id(*parts):
    value = '\0'.join(parts)
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _username_reservation_ref(collection_name, username):
    reservation_id = _stable_document_id(collection_name, username)
    return db.collection('username_reservations').document(reservation_id)


def _page_size():
    try:
        size = int(request.args.get('limit', 50))
    except ValueError as exc:
        raise ValueError("limit must be an integer") from exc
    if size < 1:
        raise ValueError("limit must be at least 1")
    return min(size, 100)


def _paged_documents(query, collection_ref, page_size):
    cursor = request.args.get('cursor')
    if cursor:
        cursor_doc = collection_ref.document(cursor).get()
        if not cursor_doc.exists:
            raise ValueError("Invalid pagination cursor")
        query = query.start_after(cursor_doc)

    docs = list(query.limit(page_size + 1).stream())
    has_more = len(docs) > page_size
    page_docs = docs[:page_size]
    next_cursor = page_docs[-1].id if has_more and page_docs else None
    return page_docs, next_cursor


def _verify_password(account_doc, account_data, password):
    stored_hash = account_data.get('password_hash')
    is_current_hash = isinstance(stored_hash, str) and stored_hash.startswith(('scrypt:', 'pbkdf2:'))

    if is_current_hash:
        try:
            password_matches = check_password_hash(stored_hash, password)
        except ValueError:
            password_matches = False
    elif isinstance(stored_hash, str):
        legacy_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        password_matches = hmac.compare_digest(stored_hash, legacy_hash)
        if not password_matches and isinstance(account_data.get('password'), str):
            password_matches = hmac.compare_digest(account_data['password'], password)
    elif isinstance(account_data.get('password'), str):
        password_matches = hmac.compare_digest(account_data['password'], password)
    else:
        password_matches = False

    if not password_matches:
        return False

    updates = {}
    if not is_current_hash:
        updates['password_hash'] = generate_password_hash(password)
    if 'password' in account_data:
        updates['password'] = firestore.DELETE_FIELD
    if updates:
        account_doc.reference.update(updates)
    return True


def _safe_str(value, max_len=2000):
    """Validate that value is a non-empty string within max_len characters."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:max_len]


def _parse_event_date(date_str):
    """
    Parse an ISO date string (with or without timezone) into an aware UTC datetime.
    Naive strings are interpreted in Asia/Kolkata (IST) timezone.
    Returns a timezone-aware datetime in UTC or raises ValueError.
    """
    if not date_str:
        raise ValueError("Date is required")
    date_str = str(date_str).strip()

    # Handle standard ISO with timezone (e.g. 2026-07-01T10:00:00+05:30, 2026-07-01T10:00:00Z)
    cleaned_iso = date_str.replace('Z', '+00:00')
    try:
        dt = datetime.fromisoformat(cleaned_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=IST)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    # Try explicit format patterns
    for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M%z'):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d'):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=IST).astimezone(timezone.utc)
        except ValueError:
            pass

    raise ValueError(f"Unrecognised date format: {date_str!r}")


def _event_is_expired(event_dict):
    """Return True if the event's date is in the past (relative to current UTC time)."""
    raw_date = event_dict.get('date')
    if raw_date is None:
        return False

    if isinstance(raw_date, str):
        try:
            event_dt = _parse_event_date(raw_date)
        except Exception:
            return False
    elif hasattr(raw_date, 'seconds'):
        # Firestore DatetimeWithNanoseconds or Timestamp
        event_dt = datetime.fromtimestamp(raw_date.seconds, tz=timezone.utc)
    elif isinstance(raw_date, datetime):
        if raw_date.tzinfo is not None:
            event_dt = raw_date.astimezone(timezone.utc)
        else:
            event_dt = raw_date.replace(tzinfo=IST).astimezone(timezone.utc)
    else:
        return False

    return event_dt < datetime.now(timezone.utc)


def _serialize_event(doc_id, event_dict):
    """Convert a Firestore event document to a JSON-serialisable dict."""
    d = dict(event_dict)
    d['id'] = doc_id
    raw_date = d.get('date')
    if raw_date is not None:
        if hasattr(raw_date, 'isoformat'):
            d['date'] = raw_date.isoformat()
        elif hasattr(raw_date, 'seconds'):
            d['date'] = datetime.fromtimestamp(raw_date.seconds, tz=timezone.utc).isoformat()
        elif isinstance(raw_date, str):
            d['date'] = raw_date

    # Expose expiry status for frontend badge rendering and registration lock
    d['expired'] = _event_is_expired(event_dict)
    d.pop('created_at', None)
    d.pop('updated_at', None)
    return d


# ----------------------------
# Page Routes
# ----------------------------

@app.route('/')
def index():
    return render_template('event.html')


@app.route('/user')
def user_page():
    return render_template('user.html')


@app.route('/user/events')
def user_events():
    return render_template('user_events.html')


@app.route('/admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')


@app.route('/settings')
def settings():
    return render_template('settings.html')


@app.route('/users')
def users():
    return render_template('users.html')


# ----------------------------
# Auth routes
# ----------------------------

@app.route('/api/auth-status', methods=['GET'])
def auth_status():
    """Return current session auth state."""
    if session.get('admin_logged_in'):
        return jsonify({'logged_in': True, 'role': 'admin', 'username': session.get('username')})
    elif session.get('user_logged_in'):
        return jsonify({'logged_in': True, 'role': 'user', 'username': session.get('username')})
    return jsonify({'logged_in': False, 'role': None, 'username': None})


@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    response = jsonify({'csrf_token': csrf_token()})
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/register/user', methods=['POST'])
@limiter.limit('5 per hour')
def register_user():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    password = data.get('password')

    if not username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    if not isinstance(password, str) or len(password) < 6 or len(password) > 1024:
        return jsonify({'success': False, 'message': 'Password must be between 6 and 1024 characters'}), 400

    try:
        users_ref = db.collection('users')
        if len(users_ref.where('username', '==', username).limit(1).get()) > 0:
            return jsonify({'success': False, 'message': 'Username already exists'}), 409

        password_hash = generate_password_hash(password)

        account_ref = users_ref.document(_stable_document_id('users', username))
        reservation_ref = _username_reservation_ref('users', username)
        batch = db.batch()
        batch.create(reservation_ref, {'account_id': account_ref.id, 'username': username})
        batch.create(account_ref, {
            'username': username,
            'password_hash': password_hash,
            'email': f"{username}@example.com",
            'role': 'user',
            'status': 'active',
            'lastLogin': firestore.SERVER_TIMESTAMP,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        batch.commit()
        return jsonify({'success': True, 'message': 'User registered successfully'})
    except AlreadyExists:
        return jsonify({'success': False, 'message': 'Username already exists'}), 409
    except Exception as e:
        app.logger.error("register_user error: %s", e)
        return jsonify({'success': False, 'message': 'Registration failed'}), 500


@app.route('/register/admin', methods=['POST'])
@require_admin_session
@limiter.limit('10 per hour')
def register_admin():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    password = data.get('password')

    if not username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    if not isinstance(password, str) or len(password) < 6 or len(password) > 1024:
        return jsonify({'success': False, 'message': 'Password must be between 6 and 1024 characters'}), 400

    try:
        admins_ref = db.collection('admins')
        if len(admins_ref.where('username', '==', username).limit(1).get()) > 0:
            return jsonify({'success': False, 'message': 'Username already exists'}), 409

        account_ref = admins_ref.document(_stable_document_id('admins', username))
        reservation_ref = _username_reservation_ref('admins', username)
        batch = db.batch()
        batch.create(reservation_ref, {'account_id': account_ref.id, 'username': username})
        batch.create(account_ref, {
            'username': username,
            'password_hash': generate_password_hash(password),
            'created_at': firestore.SERVER_TIMESTAMP
        })
        batch.commit()
        return jsonify({'success': True, 'message': 'Admin registered successfully'})
    except AlreadyExists:
        return jsonify({'success': False, 'message': 'Username already exists'}), 409
    except Exception as e:
        app.logger.error("register_admin error: %s", e)
        return jsonify({'success': False, 'message': 'Registration failed'}), 500


@app.route('/login/user', methods=['POST'])
@limiter.limit('5 per minute')
@limiter.limit('30 per hour')
def login_user():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    password = data.get('password')

    if not username or not isinstance(password, str) or not password or len(password) > 1024:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    try:
        users_ref = db.collection('users')
        results = users_ref.where('username', '==', username).limit(1).get()
        if results and results[0].to_dict().get('status', 'active') == 'active' \
                and results[0].to_dict().get('role', 'user') == 'user' \
                and _verify_password(results[0], results[0].to_dict(), password):
            session.clear()
            session['user_logged_in'] = True
            session['username'] = username
            session['_csrf_token'] = secrets.token_urlsafe(32)
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    except Exception as e:
        app.logger.error("login_user error: %s", e)
        return jsonify({'success': False, 'message': 'Login failed'}), 500


@app.route('/login/admin', methods=['POST'])
@limiter.limit('5 per minute')
@limiter.limit('30 per hour')
def login_admin():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    password = data.get('password')

    if not username or not isinstance(password, str) or not password or len(password) > 1024:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    try:
        admins_ref = db.collection('admins')
        results = admins_ref.where('username', '==', username).limit(1).get()
        account_doc = results[0] if results else None
        account_data = account_doc.to_dict() if account_doc else None
        account_source = 'admins'
        if not account_doc:
            admin_users = db.collection('users').where('username', '==', username) \
                .where('role', '==', 'admin').limit(1).get()
            if admin_users and admin_users[0].to_dict().get('status', 'active') == 'active':
                account_doc = admin_users[0]
                account_data = account_doc.to_dict()
                account_source = 'users'

        if account_doc and account_data and _verify_password(account_doc, account_data, password):
            session.clear()
            session['admin_logged_in'] = True
            session['username'] = username
            session['admin_account_source'] = account_source
            if account_source == 'users':
                session['admin_account_id'] = account_doc.id
            session['_csrf_token'] = secrets.token_urlsafe(32)
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    except Exception as e:
        app.logger.error("login_admin error: %s", e)
        return jsonify({'success': False, 'message': 'Login failed'}), 500


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


# ----------------------------
# Event Management Routes
# ----------------------------

@app.route('/api/events', methods=['GET'])
def get_events():
    """
    Return events from Firestore.
    Query param: ?include_expired=true  to include past/expired events.
    By default only active (non-expired) events are returned.
    """
    include_expired = request.args.get('include_expired', 'false').lower() == 'true'
    try:
        page_size = _page_size()
        events_ref = db.collection('events')
        query = events_ref.order_by('date', direction=firestore.Query.ASCENDING)
        docs, next_cursor = _paged_documents(query, events_ref, page_size)
        result = []
        for doc in docs:
            d = doc.to_dict()
            expired = _event_is_expired(d)
            if not include_expired and expired:
                continue
            result.append(_serialize_event(doc.id, d))
        return jsonify({
            'events': result,
            'next_cursor': next_cursor
        })
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        app.logger.error("get_events error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch events'}), 500


@app.route('/api/events', methods=['POST'])
@require_admin_session
def create_event():
    data = request.get_json(silent=True) or {}
    name = _safe_str(data.get('name'), 200)
    location = _safe_str(data.get('location'), 200)
    description = _safe_str(data.get('description'), 2000)

    if not name:
        return jsonify({'success': False, 'error': 'Event name is required'}), 400
    if not location:
        return jsonify({'success': False, 'error': 'Location is required'}), 400
    if not description:
        return jsonify({'success': False, 'error': 'Description is required'}), 400

    try:
        date_obj = _parse_event_date(data.get('date'))
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400

    try:
        events_ref = db.collection('events')
        if len(events_ref.where('name', '==', name).limit(1).get()) > 0:
            return jsonify({'success': False, 'error': 'Event with this name already exists'}), 409

        event_ref = events_ref.document()
        name_ref = db.collection('event_names').document(_stable_document_id(name))
        batch = db.batch()
        batch.create(name_ref, {'event_id': event_ref.id, 'name': name})
        batch.create(event_ref, {
            'name': name,
            'date': date_obj,
            'location': location,
            'description': description,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        batch.commit()
        return jsonify({'success': True, 'id': event_ref.id})
    except AlreadyExists:
        return jsonify({'success': False, 'error': 'Event with this name already exists'}), 409
    except Exception as e:
        app.logger.error("create_event error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to create event'}), 500


@app.route('/api/events/<event_id>', methods=['GET'])
def get_event(event_id):
    try:
        event_ref = db.collection('events').document(event_id)
        event = event_ref.get()
        if event.exists:
            return jsonify(_serialize_event(event.id, event.to_dict()))
        return jsonify({'success': False, 'error': 'Event not found'}), 404
    except Exception as e:
        app.logger.error("get_event error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch event'}), 500


@app.route('/api/events/<event_id>', methods=['PUT'])
@require_admin_session
def update_event(event_id):
    data = request.get_json(silent=True) or {}
    name = _safe_str(data.get('name'), 200)
    location = _safe_str(data.get('location'), 200)
    description = _safe_str(data.get('description'), 2000)

    if not name:
        return jsonify({'success': False, 'error': 'Event name is required'}), 400
    if not location:
        return jsonify({'success': False, 'error': 'Location is required'}), 400
    if not description:
        return jsonify({'success': False, 'error': 'Description is required'}), 400

    try:
        date_obj = _parse_event_date(data.get('date'))
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400

    try:
        events_ref = db.collection('events')
        event_ref = events_ref.document(event_id)
        current_event = event_ref.get()
        if not current_event.exists:
            return jsonify({'success': False, 'error': 'Event not found'}), 404

        for doc in events_ref.where('name', '==', name).stream():
            if doc.id != event_id:
                return jsonify({'success': False, 'error': 'Another event with this name already exists'}), 409

        old_name = current_event.to_dict().get('name')
        name_ref = db.collection('event_names').document(_stable_document_id(name))
        reservation = name_ref.get()
        if reservation.exists and reservation.to_dict().get('event_id') != event_id:
            return jsonify({'success': False, 'error': 'Another event with this name already exists'}), 409

        batch = db.batch()
        if not reservation.exists:
            batch.create(name_ref, {'event_id': event_id, 'name': name})
        if old_name and old_name != name:
            old_name_ref = db.collection('event_names').document(_stable_document_id(old_name))
            old_reservation = old_name_ref.get()
            if old_reservation.exists and old_reservation.to_dict().get('event_id') == event_id:
                batch.delete(old_name_ref)
        batch.update(event_ref, {
            'name': name,
            'date': date_obj,
            'location': location,
            'description': description,
            'updated_at': firestore.SERVER_TIMESTAMP
        })
        batch.commit()
        return jsonify({'success': True})
    except AlreadyExists:
        return jsonify({'success': False, 'error': 'Another event with this name already exists'}), 409
    except Exception as e:
        app.logger.error("update_event error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to update event'}), 500


@app.route('/api/events/<event_id>', methods=['DELETE'])
@require_admin_session
def delete_event(event_id):
    try:
        events_ref = db.collection('events')
        event_ref = events_ref.document(event_id)
        event_doc = event_ref.get()
        if not event_doc.exists:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
        batch = db.batch()
        event_name = event_doc.to_dict().get('name')
        if event_name:
            name_ref = db.collection('event_names').document(_stable_document_id(event_name))
            name_doc = name_ref.get()
            if name_doc.exists and name_doc.to_dict().get('event_id') == event_id:
                batch.delete(name_ref)
        batch.delete(event_ref)
        batch.commit()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error("delete_event error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to delete event'}), 500


# ----------------------------
# Registration Routes
# ----------------------------

@app.route('/api/events/<event_id>/register', methods=['POST'])
def register_for_event(event_id):
    if not session.get('user_logged_in') or not session.get('username'):
        return jsonify({'success': False, 'error': 'Unauthorized: User login required'}), 401
    username = session['username']

    try:
        # 1. Verify event exists
        event_doc = db.collection('events').document(event_id).get()
        if not event_doc.exists:
            return jsonify({'success': False, 'error': 'Event not found'}), 404

        event_data = event_doc.to_dict()

        # 2. Enforce expiry — reject registration for ended events
        if _event_is_expired(event_data):
            return jsonify({'success': False, 'error': 'Registration is closed — this event has ended'}), 400

        # 3. Require the user to exist (no auto-creation)
        users_ref = db.collection('users')
        user_docs = users_ref.where('username', '==', username).limit(1).get()
        if len(user_docs) == 0:
            return jsonify({'success': False, 'error': 'User account is unavailable'}), 401
        if user_docs[0].to_dict().get('status', 'active') != 'active':
            session.clear()
            return jsonify({'success': False, 'error': 'User account is inactive'}), 403

        # 4. Check duplicate registration
        reg_ref = db.collection('registrations')
        if len(reg_ref.where('event_id', '==', event_id)
                      .where('username', '==', username).limit(1).get()) > 0:
            return jsonify({'success': False, 'error': 'Already registered for this event'}), 409

        # 5. Create registration record
        registration_id = _stable_document_id(event_id, username)
        reg_ref.document(registration_id).create({
            'event_id': event_id,
            'username': username,
            'registered_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Registered successfully'})
    except AlreadyExists:
        return jsonify({'success': False, 'error': 'Already registered for this event'}), 409
    except Exception as e:
        app.logger.error("register_for_event error: %s", e)
        return jsonify({'success': False, 'error': 'Registration failed'}), 500


@app.route('/api/events/<event_id>/registrations', methods=['GET'])
@require_admin_session
def get_event_registrations(event_id):
    try:
        page_size = _page_size()
        reg_ref = db.collection('registrations')
        query = reg_ref.where('event_id', '==', event_id).order_by('__name__')
        registrations, next_cursor = _paged_documents(query, reg_ref, page_size)
        result = []
        for reg in registrations:
            d = reg.to_dict()
            d['id'] = reg.id
            ra = d.get('registered_at')
            if ra is not None and hasattr(ra, 'isoformat'):
                d['registered_at'] = ra.isoformat()
            elif ra is not None and hasattr(ra, 'seconds'):
                d['registered_at'] = datetime.fromtimestamp(ra.seconds, tz=timezone.utc).isoformat()
            result.append(d)
        return jsonify({'registrations': result, 'next_cursor': next_cursor})
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        app.logger.error("get_event_registrations error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch registrations'}), 500


@app.route('/api/events/<event_id>/registration', methods=['GET'])
@require_user_session
def get_user_event_registration(event_id):
    if session.get('admin_logged_in') and not session.get('user_logged_in'):
        return jsonify({'registered': False})
    try:
        reg = db.collection('registrations').where('event_id', '==', event_id) \
            .where('username', '==', session['username']).limit(1).get()
        return jsonify({'registered': bool(reg)})
    except Exception as e:
        app.logger.error("get_user_event_registration error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch registration status'}), 500


# ----------------------------
# User Management Routes
# ----------------------------

@app.route('/api/users', methods=['GET'])
@require_admin_session
def get_users():
    try:
        page_size = _page_size()
        users_ref = db.collection('users')
        user_list = []
        query = users_ref.order_by('__name__')
        users, next_cursor = _paged_documents(query, users_ref, page_size)
        for user in users:
            d = user.to_dict()
            d['id'] = user.id
            # Strip passwords and hashes
            d.pop('password', None)
            d.pop('password_hash', None)
            # Serialize timestamps
            for field in ('lastLogin', 'created_at', 'updated_at'):
                ts = d.get(field)
                if ts is not None and hasattr(ts, 'isoformat'):
                    d[field] = ts.isoformat()
                elif ts is not None and hasattr(ts, 'seconds'):
                    d[field] = datetime.fromtimestamp(ts.seconds, tz=timezone.utc).isoformat()
            user_list.append(d)
        return jsonify({
            'success': True,
            'users': user_list,
            'next_cursor': next_cursor
        })
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        app.logger.error("get_users error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch users'}), 500


@app.route('/api/users', methods=['POST'])
@require_admin_session
@limiter.limit('10 per hour')
def create_user():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    email = _safe_str(data.get('email'), 200)
    role = data.get('role', 'user')
    status = data.get('status', 'active')
    password = data.get('password')

    if not username:
        return jsonify({'success': False, 'error': 'Username is required'}), 400
    if role not in ('user', 'admin'):
        return jsonify({'success': False, 'error': 'Invalid role'}), 400
    if status not in ('active', 'inactive'):
        return jsonify({'success': False, 'error': 'Invalid status'}), 400
    if not isinstance(password, str) or len(password) < 6 or len(password) > 1024:
        return jsonify({'success': False, 'error': 'Password must be between 6 and 1024 characters'}), 400

    try:
        users_ref = db.collection('users')
        if len(users_ref.where('username', '==', username).limit(1).get()) > 0:
            return jsonify({'success': False, 'error': 'Username already exists'}), 409

        doc_ref = users_ref.document(_stable_document_id('users', username))
        reservation_ref = _username_reservation_ref('users', username)
        batch = db.batch()
        batch.create(reservation_ref, {'account_id': doc_ref.id, 'username': username})
        batch.create(doc_ref, {
            'username': username,
            'password_hash': generate_password_hash(password),
            'email': email or f"{username}@example.com",
            'role': role,
            'status': status,
            'lastLogin': None,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        batch.commit()
        return jsonify({'success': True, 'id': doc_ref.id})
    except AlreadyExists:
        return jsonify({'success': False, 'error': 'Username already exists'}), 409
    except Exception as e:
        app.logger.error("create_user error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to create user'}), 500


@app.route('/api/users/<user_id>', methods=['PUT'])
@require_admin_session
def update_user(user_id):
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    email = _safe_str(data.get('email'), 200)
    role = data.get('role', 'user')
    status = data.get('status', 'active')

    if not username:
        return jsonify({'success': False, 'error': 'Username is required'}), 400
    if role not in ('user', 'admin'):
        return jsonify({'success': False, 'error': 'Invalid role'}), 400
    if status not in ('active', 'inactive'):
        return jsonify({'success': False, 'error': 'Invalid status'}), 400

    try:
        users_ref = db.collection('users')
        user_ref = users_ref.document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        current_user = user_doc.to_dict()
        existing_users = users_ref.where('username', '==', username).limit(2).get()
        if any(user.id != user_id for user in existing_users):
            return jsonify({'success': False, 'error': 'Username already exists'}), 409

        batch = db.batch()
        if current_user.get('username') != username:
            reservation_ref = _username_reservation_ref('users', username)
            reservation = reservation_ref.get()
            if reservation.exists and reservation.to_dict().get('account_id') != user_id:
                return jsonify({'success': False, 'error': 'Username already exists'}), 409
            if not reservation.exists:
                batch.create(reservation_ref, {'account_id': user_id, 'username': username})
            old_reservation_ref = _username_reservation_ref('users', current_user.get('username', ''))
            old_reservation = old_reservation_ref.get()
            if old_reservation.exists and old_reservation.to_dict().get('account_id') == user_id:
                batch.delete(old_reservation_ref)
        batch.update(user_ref, {
            'username': username,
            'email': email or f"{username}@example.com",
            'role': role,
            'status': status,
            'updated_at': firestore.SERVER_TIMESTAMP
        })
        batch.commit()
        return jsonify({'success': True})
    except AlreadyExists:
        return jsonify({'success': False, 'error': 'Username already exists'}), 409
    except Exception as e:
        app.logger.error("update_user error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to update user'}), 500


@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_admin_session
def delete_user(user_id):
    try:
        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        user_data = user_doc.to_dict()
        batch = db.batch()
        reservation_ref = _username_reservation_ref('users', user_data.get('username', ''))
        reservation = reservation_ref.get()
        if reservation.exists and reservation.to_dict().get('account_id') == user_id:
            batch.delete(reservation_ref)
        batch.delete(user_ref)
        batch.commit()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error("delete_user error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to delete user'}), 500


# ----------------------------
# Settings Routes
# ----------------------------

@app.route('/api/settings', methods=['GET'])
@require_admin_session
def get_settings():
    try:
        settings_ref = db.collection('settings').document('app_settings')
        settings_doc = settings_ref.get()
        if settings_doc.exists:
            return jsonify(settings_doc.to_dict())
        return jsonify({
            'theme': 'blue',
            'darkMode': False,
            'defaultView': 'grid',
            'eventsPerPage': 12,
            'notifications': True,
            'emailNotifications': False,
            'emailAddress': ''
        })
    except Exception as e:
        app.logger.error("get_settings error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch settings'}), 500


@app.route('/api/settings', methods=['POST'])
@require_admin_session
def update_settings():
    data = request.get_json(silent=True) or {}
    allowed_keys = {'theme', 'darkMode', 'defaultView', 'eventsPerPage',
                    'notifications', 'emailNotifications', 'emailAddress'}
    safe_data = {k: v for k, v in data.items() if k in allowed_keys}
    try:
        db.collection('settings').document('app_settings').set(safe_data, merge=True)
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error("update_settings error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to save settings'}), 500


# ----------------------------
# Health check
# ----------------------------

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        db.collection('users').limit(1).get()
        return jsonify({'success': True, 'message': 'Firestore connection OK'})
    except Exception as e:
        app.logger.error("health_check error: %s", e)
        return jsonify({'success': False, 'error': 'Firestore connection failed'}), 500


# ----------------------------
# Run the server
# ----------------------------
if __name__ == '__main__':
    import sys
    try:
        init_firebase()
    except Exception as e:
        print(f"\n[FATAL STARTUP ERROR] {e}\n", file=sys.stderr)
        sys.exit(1)

    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
