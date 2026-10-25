from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import os
from datetime import datetime, timezone, timedelta
from functools import wraps

app = Flask(__name__)

# SECRET_KEY is required for session-based auth guard. Set via env var in production.
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')

# Restrict CORS to localhost in development. Set ALLOWED_ORIGIN env var in production.
_allowed_origin = os.environ.get('ALLOWED_ORIGIN', 'http://localhost:5000')
CORS(app, origins=[_allowed_origin], supports_credentials=True)

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
                'error': f"Database service unavailable: {e}"
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


@app.route('/register/user', methods=['POST'])
def register_user():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    password = data.get('password')

    if not username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    if not password or len(str(password)) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    try:
        users_ref = db.collection('users')
        if len(users_ref.where('username', '==', username).limit(1).get()) > 0:
            return jsonify({'success': False, 'message': 'Username already exists'})

        import hashlib
        password_hash = hashlib.sha256(str(password).encode()).hexdigest()

        users_ref.add({
            'username': username,
            'password_hash': password_hash,
            'email': f"{username}@example.com",
            'role': 'user',
            'status': 'active',
            'lastLogin': firestore.SERVER_TIMESTAMP,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'User registered successfully'})
    except Exception as e:
        app.logger.error("register_user error: %s", e)
        return jsonify({'success': False, 'message': 'Registration failed'}), 500


@app.route('/register/admin', methods=['POST'])
def register_admin():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    password = data.get('password')

    if not username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    if not password or len(str(password)) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    try:
        admins_ref = db.collection('admins')
        if len(admins_ref.where('username', '==', username).limit(1).get()) > 0:
            return jsonify({'success': False, 'message': 'Username already exists'})

        import hashlib
        password_hash = hashlib.sha256(str(password).encode()).hexdigest()

        admins_ref.add({
            'username': username,
            'password_hash': password_hash,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Admin registered successfully'})
    except Exception as e:
        app.logger.error("register_admin error: %s", e)
        return jsonify({'success': False, 'message': 'Registration failed'}), 500


@app.route('/login/user', methods=['POST'])
def login_user():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    try:
        import hashlib
        password_hash = hashlib.sha256(str(password).encode()).hexdigest()

        users_ref = db.collection('users')
        results = users_ref.where('username', '==', username) \
                           .where('password_hash', '==', password_hash).limit(1).get()
        if not results:
            results = users_ref.where('username', '==', username) \
                               .where('password', '==', password).limit(1).get()

        if results:
            session['user_logged_in'] = True
            session['username'] = username
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    except Exception as e:
        app.logger.error("login_user error: %s", e)
        return jsonify({'success': False, 'message': 'Login failed'}), 500


@app.route('/login/admin', methods=['POST'])
def login_admin():
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Credentials required'}), 400

    try:
        import hashlib
        password_hash = hashlib.sha256(str(password).encode()).hexdigest()

        admins_ref = db.collection('admins')
        results = admins_ref.where('username', '==', username) \
                            .where('password_hash', '==', password_hash).limit(1).get()
        if not results:
            results = admins_ref.where('username', '==', username) \
                                .where('password', '==', password).limit(1).get()

        if results:
            session['admin_logged_in'] = True
            session['username'] = username
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    except Exception as e:
        app.logger.error("login_admin error: %s", e)
        return jsonify({'success': False, 'message': 'Login failed'}), 500


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    if request.method == 'GET':
        return redirect(url_for('index'))
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
        events_ref = db.collection('events')
        docs = events_ref.order_by('date', direction=firestore.Query.ASCENDING).stream()
        result = []
        for doc in docs:
            d = doc.to_dict()
            expired = _event_is_expired(d)
            if not include_expired and expired:
                continue
            result.append(_serialize_event(doc.id, d))
        return jsonify(result)
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
            return jsonify({'success': False, 'error': 'Event with this name already exists'})

        _, doc_ref = events_ref.add({
            'name': name,
            'date': date_obj,
            'location': location,
            'description': description,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'id': doc_ref.id})
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
        for doc in events_ref.where('name', '==', name).stream():
            if doc.id != event_id:
                return jsonify({'success': False, 'error': 'Another event with this name already exists'})

        events_ref.document(event_id).update({
            'name': name,
            'date': date_obj,
            'location': location,
            'description': description,
            'updated_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error("update_event error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to update event'}), 500


@app.route('/api/events/<event_id>', methods=['DELETE'])
@require_admin_session
def delete_event(event_id):
    try:
        db.collection('events').document(event_id).delete()
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error("delete_event error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to delete event'}), 500


# ----------------------------
# Registration Routes
# ----------------------------

@app.route('/api/events/<event_id>/register', methods=['POST'])
def register_for_event(event_id):
    data = request.get_json(silent=True) or {}
    username = _safe_str(data.get('username'), 50)
    if not username:
        return jsonify({'success': False, 'error': 'Username is required'}), 400

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
            return jsonify({'success': False, 'error': 'User not found. Please register an account first.'}), 404

        # 4. Check duplicate registration
        reg_ref = db.collection('registrations')
        if len(reg_ref.where('event_id', '==', event_id)
                      .where('username', '==', username).limit(1).get()) > 0:
            return jsonify({'success': False, 'error': 'Already registered for this event'})

        # 5. Create registration record
        reg_ref.add({
            'event_id': event_id,
            'username': username,
            'registered_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Registered successfully'})
    except Exception as e:
        app.logger.error("register_for_event error: %s", e)
        return jsonify({'success': False, 'error': 'Registration failed'}), 500


@app.route('/api/events/<event_id>/registrations', methods=['GET'])
def get_event_registrations(event_id):
    """
    Return registration list for an event.
    Admin sees full participant details.
    Regular users see their own record or masked attendance names to protect user privacy.
    """
    try:
        reg_ref = db.collection('registrations')
        registrations = reg_ref.where('event_id', '==', event_id).stream()
        is_admin = session.get('admin_logged_in', False)
        current_username = session.get('username')

        result = []
        for reg in registrations:
            d = reg.to_dict()
            d['id'] = reg.id
            ra = d.get('registered_at')
            if ra is not None and hasattr(ra, 'isoformat'):
                d['registered_at'] = ra.isoformat()
            elif ra is not None and hasattr(ra, 'seconds'):
                d['registered_at'] = datetime.fromtimestamp(ra.seconds, tz=timezone.utc).isoformat()

            if is_admin:
                result.append(d)
            elif current_username and d.get('username') == current_username:
                result.append(d)
            else:
                masked = dict(d)
                uname = masked.get('username', '')
                masked['username'] = uname[:2] + '***' if len(uname) > 2 else 'Attendee'
                result.append(masked)

        return jsonify(result)
    except Exception as e:
        app.logger.error("get_event_registrations error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch registrations'}), 500


# ----------------------------
# User Management Routes
# ----------------------------

@app.route('/api/users', methods=['GET'])
@require_admin_session
def get_users():
    try:
        users_ref = db.collection('users')
        user_list = []
        for user in users_ref.stream():
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
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        app.logger.error("get_users error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to fetch users'}), 500


@app.route('/api/users', methods=['POST'])
@require_admin_session
def create_user():
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
        _, doc_ref = users_ref.add({
            'username': username,
            'email': email or f"{username}@example.com",
            'role': role,
            'status': status,
            'lastLogin': firestore.SERVER_TIMESTAMP,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'id': doc_ref.id})
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
        db.collection('users').document(user_id).update({
            'username': username,
            'email': email or f"{username}@example.com",
            'role': role,
            'status': status,
            'updated_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error("update_user error: %s", e)
        return jsonify({'success': False, 'error': 'Failed to update user'}), 500


@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_admin_session
def delete_user(user_id):
    try:
        db.collection('users').document(user_id).delete()
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
