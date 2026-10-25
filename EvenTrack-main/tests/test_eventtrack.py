import os
import sys
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import even
from even import app, _parse_event_date, _event_is_expired, _serialize_event, IST, init_firebase

# Inject a mock Firestore client so tests are completely independent of production credentials
_mock_firestore = MagicMock(name='MockFirestoreClient')
init_firebase(client=_mock_firestore)


@pytest.fixture(autouse=True)
def reset_mock_db():
    """Ensure even.db is always restored to _mock_firestore before and after each test."""
    even.db = _mock_firestore
    yield
    even.db = _mock_firestore


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key-for-testing'
    return app.test_client()


@pytest.fixture
def admin_client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key-for-testing'
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['username'] = 'testadmin'
    return c


@pytest.fixture
def user_client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key-for-testing'
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['user_logged_in'] = True
        sess['username'] = 'regularuser'
    return c


# ============================================================================
# Case 1: Unauthenticated visitors cannot access protected admin operations
# ============================================================================
def test_unauthenticated_cannot_access_admin_operations(client):
    """Verify that every protected admin endpoint strictly returns 401 when unauthenticated."""
    assert client.post('/api/events', json={'name': 'Hackathon'}).status_code == 401
    assert client.put('/api/events/dummy-id', json={'name': 'Update'}).status_code == 401
    assert client.delete('/api/events/dummy-id').status_code == 401
    assert client.get('/api/users').status_code == 401
    assert client.post('/api/users', json={'username': 'hacker'}).status_code == 401
    assert client.put('/api/users/dummy-id', json={'role': 'admin'}).status_code == 401
    assert client.delete('/api/users/dummy-id').status_code == 401
    assert client.get('/api/settings').status_code == 401
    assert client.post('/api/settings', json={'theme': 'dark'}).status_code == 401


# ============================================================================
# Case 2: Regular users cannot perform admin-only operations
# ============================================================================
def test_regular_user_cannot_perform_admin_operations(user_client):
    """Verify that a logged-in regular user is blocked from admin privileges (privilege escalation prevention)."""
    assert user_client.post('/api/events', json={'name': 'Malicious Event'}).status_code == 401
    assert user_client.get('/api/users').status_code == 401
    assert user_client.delete('/api/events/some-event-id').status_code == 401
    assert user_client.get('/api/settings').status_code == 401
    assert user_client.post('/api/settings', json={'theme': 'red'}).status_code == 401


# ============================================================================
# Case 3: Users cannot access or modify other users' registrations without authorization
# ============================================================================
def test_user_registration_privacy(client):
    """Verify that non-admin visitors see masked participant names, preserving attendee privacy."""
    mock_reg1 = MagicMock()
    mock_reg1.id = 'reg1'
    mock_reg1.to_dict.return_value = {
        'username': 'john_doe',
        'event_id': 'evt1',
        'registered_at': datetime.now(timezone.utc)
    }

    mock_reg2 = MagicMock()
    mock_reg2.id = 'reg2'
    mock_reg2.to_dict.return_value = {
        'username': 'regularuser',
        'event_id': 'evt1',
        'registered_at': datetime.now(timezone.utc)
    }

    with patch.object(even.db, 'collection') as mock_collection:
        mock_reg_ref = MagicMock()
        mock_collection.return_value = mock_reg_ref
        mock_reg_ref.where.return_value.stream.return_value = [mock_reg1, mock_reg2]

        # 1. Unauthenticated visitor: all usernames masked
        res_anon = client.get('/api/events/evt1/registrations')
        assert res_anon.status_code == 200
        data_anon = res_anon.get_json()
        assert len(data_anon) == 2
        assert data_anon[0]['username'] == 'jo***'
        assert data_anon[1]['username'] == 're***'

        # 2. Regular user: sees own name unmasked, other attendee masked
        with client.session_transaction() as sess:
            sess['user_logged_in'] = True
            sess['username'] = 'regularuser'

        res_user = client.get('/api/events/evt1/registrations')
        data_user = res_user.get_json()
        assert data_user[0]['username'] == 'jo***'
        assert data_user[1]['username'] == 'regularuser'

        # 3. Admin: sees all names unmasked
        with client.session_transaction() as sess:
            sess['admin_logged_in'] = True
            sess['user_logged_in'] = False
            sess['username'] = 'testadmin'

        res_admin = client.get('/api/events/evt1/registrations')
        data_admin = res_admin.get_json()
        assert data_admin[0]['username'] == 'john_doe'
        assert data_admin[1]['username'] == 'regularuser'


# ============================================================================
# Case 4: Invalid event input is rejected
# ============================================================================
def test_invalid_event_input_is_rejected(admin_client):
    """Verify that missing fields, empty strings, and malformed dates are rejected with 400 Bad Request."""
    # Missing name
    res = admin_client.post('/api/events', json={
        'date': '2026-12-01T10:00',
        'location': 'Auditorium',
        'description': 'Tech Talk'
    })
    assert res.status_code == 400
    assert 'name is required' in res.get_json()['error'].lower()

    # Empty name
    res = admin_client.post('/api/events', json={
        'name': '   ',
        'date': '2026-12-01T10:00',
        'location': 'Auditorium',
        'description': 'Tech Talk'
    })
    assert res.status_code == 400

    # Missing location
    res = admin_client.post('/api/events', json={
        'name': 'Python Workshop',
        'date': '2026-12-01T10:00',
        'description': 'Tech Talk'
    })
    assert res.status_code == 400

    # Invalid date format
    res = admin_client.post('/api/events', json={
        'name': 'Python Workshop',
        'date': 'invalid-date-string-1234',
        'location': 'Room 101',
        'description': 'Tech Talk'
    })
    assert res.status_code == 400
    assert 'unrecognised date format' in res.get_json()['error'].lower()


# ============================================================================
# Case 5 & 6 & 7: Registration lifecycle, deadlines, and backend enforcement
# ============================================================================
def test_registration_succeeds_before_deadline(client):
    """Registration succeeds when event date is in the future and user exists."""
    future_date = datetime.now(timezone.utc) + timedelta(days=10)

    mock_event_doc = MagicMock()
    mock_event_doc.exists = True
    mock_event_doc.to_dict.return_value = {
        'name': 'Future Conf',
        'date': future_date,
        'location': 'Online',
        'description': 'Upcoming'
    }

    mock_user_doc = MagicMock()
    mock_user_doc.exists = True

    with patch.object(even.db, 'collection') as mock_coll:
        def collection_side_effect(name):
            mock_ref = MagicMock()
            if name == 'events':
                mock_ref.document.return_value.get.return_value = mock_event_doc
            elif name == 'users':
                # User exists
                mock_ref.where.return_value.limit.return_value.get.return_value = [mock_user_doc]
            elif name == 'registrations':
                # Not yet registered
                mock_ref.where.return_value.where.return_value.limit.return_value.get.return_value = []
                mock_ref.add.return_value = (None, MagicMock(id='new-reg-id'))
            return mock_ref

        mock_coll.side_effect = collection_side_effect

        res = client.post('/api/events/evt-future/register', json={'username': 'existinguser'})
        assert res.status_code == 200
        assert res.get_json()['success'] is True


def test_registration_rejected_at_or_after_deadline(client):
    """Registration is rejected with 400 when event is in the past."""
    past_date = datetime.now(timezone.utc) - timedelta(days=2)

    mock_event_doc = MagicMock()
    mock_event_doc.exists = True
    mock_event_doc.to_dict.return_value = {
        'name': 'Old Summit',
        'date': past_date,
        'location': 'Auditorium',
        'description': 'Finished'
    }

    with patch.object(even.db, 'collection') as mock_coll:
        mock_ref = MagicMock()
        mock_ref.document.return_value.get.return_value = mock_event_doc
        mock_coll.return_value = mock_ref

        res = client.post('/api/events/evt-past/register', json={'username': 'attendee1'})
        assert res.status_code == 400
        assert res.get_json()['success'] is False
        assert 'registration is closed' in res.get_json()['error'].lower()


def test_direct_backend_request_cannot_bypass_closed_registration(client):
    """Direct API POST request cannot bypass the closed-registration rule."""
    past_date = datetime.now(timezone.utc) - timedelta(hours=1)

    mock_event_doc = MagicMock()
    mock_event_doc.exists = True
    mock_event_doc.to_dict.return_value = {
        'name': 'Closed Event',
        'date': past_date,
        'location': 'Hall A',
        'description': 'Event ended 1 hour ago'
    }

    with patch.object(even.db, 'collection') as mock_coll:
        mock_ref = MagicMock()
        mock_ref.document.return_value.get.return_value = mock_event_doc
        mock_coll.return_value = mock_ref

        # Direct HTTP POST without browser UI
        res = client.post('/api/events/evt-closed/register', json={'username': 'direct_api_hacker'})
        assert res.status_code == 400
        assert 'registration is closed' in res.get_json()['error'].lower()


# ============================================================================
# Case 8: Ended events disappear from active admin list
# ============================================================================
def test_ended_events_disappear_from_active_list(client):
    """Verify that default GET /api/events excludes ended events, but include_expired=true includes them."""
    past_event = MagicMock()
    past_event.id = 'past1'
    past_event.to_dict.return_value = {
        'name': 'Past Event',
        'date': datetime.now(timezone.utc) - timedelta(days=5),
        'location': 'City Hall',
        'description': 'Already finished'
    }

    active_event = MagicMock()
    active_event.id = 'active1'
    active_event.to_dict.return_value = {
        'name': 'Active Event',
        'date': datetime.now(timezone.utc) + timedelta(days=5),
        'location': 'Campus',
        'description': 'Coming soon'
    }

    with patch.object(even.db, 'collection') as mock_coll:
        mock_ref = MagicMock()
        mock_ref.order_by.return_value.stream.return_value = [past_event, active_event]
        mock_coll.return_value = mock_ref

        # 1. Default request: only active event returned
        res_default = client.get('/api/events')
        data_default = res_default.get_json()
        assert len(data_default) == 1
        assert data_default[0]['id'] == 'active1'
        assert data_default[0]['expired'] is False

        # 2. Request with include_expired=true: both returned with correct status
        res_all = client.get('/api/events?include_expired=true')
        data_all = res_all.get_json()
        assert len(data_all) == 2
        past_found = next(e for e in data_all if e['id'] == 'past1')
        active_found = next(e for e in data_all if e['id'] == 'active1')
        assert past_found['expired'] is True
        assert active_found['expired'] is False


# ============================================================================
# Case 9: Expiry does not destroy event history or registration records
# ============================================================================
def test_expiry_does_not_destroy_history_or_records():
    """Verify _serialize_event flags expired status without mutating or deleting underlying records."""
    past_date = datetime.now(timezone.utc) - timedelta(days=30)
    event_dict = {
        'name': 'Annual Gala 2025',
        'date': past_date,
        'location': 'Grand Ballroom',
        'description': 'Historical Gala',
        'created_at': 'timestamp-marker'
    }

    serialized = _serialize_event('gala-2025', event_dict)
    assert serialized['id'] == 'gala-2025'
    assert serialized['expired'] is True
    # The original dict was not deleted or corrupted
    assert event_dict['name'] == 'Annual Gala 2025'
    assert event_dict['date'] == past_date


# ============================================================================
# Case 10: Date & Time Parsing & IST Timezone Correctness
# ============================================================================
def test_date_parsing_and_timezone():
    """Verify timezone handling for ISO strings and naive Asia/Kolkata dates."""
    # 1. Aware ISO with UTC Z
    dt_utc = _parse_event_date('2026-08-15T10:00:00Z')
    assert dt_utc.tzinfo == timezone.utc
    assert dt_utc.hour == 10

    # 2. Naive string treated as IST (Asia/Kolkata = UTC+5:30)
    dt_ist = _parse_event_date('2026-08-15T15:30:00')
    assert dt_ist.tzinfo == timezone.utc
    # 15:30 IST is 10:00 UTC
    assert dt_ist.hour == 10
    assert dt_ist.minute == 0


# ============================================================================
# Case 11: Settings and sidebar navigation
# ============================================================================
def test_settings_allowed_keys_validation(admin_client):
    """Verify update_settings only allows known keys, discarding unexpected properties."""
    with patch.object(even.db, 'collection') as mock_coll:
        mock_doc = MagicMock()
        mock_coll.return_value.document.return_value = mock_doc

        payload = {
            'theme': 'green',
            'darkMode': True,
            'defaultView': 'list',
            'eventsPerPage': 25,
            'notifications': True,
            'emailNotifications': True,
            'emailAddress': 'admin@eventtrack.local',
            'malicious_key': 'DROP TABLE users'  # Should be discarded
        }

        res = admin_client.post('/api/settings', json=payload)
        assert res.status_code == 200
        assert res.get_json()['success'] is True

        # Verify set was called without malicious_key
        called_arg = mock_doc.set.call_args[0][0]
        assert 'malicious_key' not in called_arg
        assert called_arg['theme'] == 'green'


# ============================================================================
# Case 12: HTML routes render cleanly with EventTrack branding & security
# ============================================================================
def test_all_html_pages_render(client):
    """Verify all front-end HTML templates render with status 200 and correct branding."""
    pages = ['/', '/user', '/user/events', '/admin', '/settings', '/users']
    for page in pages:
        res = client.get(page)
        assert res.status_code == 200, f"Page {page} failed to render"
        html = res.data.decode('utf-8')
        assert 'EventTrack' in html, f"EventTrack branding missing from {page}"
        assert 'viewport' in html, f"Responsive viewport meta tag missing from {page}"


def test_auth_status_and_logout(client):
    """Verify session management, /api/auth-status, and /logout."""
    # Anon check
    res1 = client.get('/api/auth-status')
    assert res1.get_json()['logged_in'] is False

    # Simulate admin login
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['username'] = 'boss'

    res2 = client.get('/api/auth-status')
    assert res2.get_json()['logged_in'] is True
    assert res2.get_json()['role'] == 'admin'

    # Logout
    res_logout = client.post('/logout')
    assert res_logout.get_json()['success'] is True

    res3 = client.get('/api/auth-status')
    assert res3.get_json()['logged_in'] is False


# ============================================================================
# Additional Security & Integrity Tests
# ============================================================================
def test_password_hashing_security(client):
    """Verify that passwords are stored as SHA256 hashes and not in plaintext."""
    import hashlib
    with patch.object(even.db, 'collection') as mock_coll:
        mock_ref = MagicMock()
        mock_ref.where.return_value.limit.return_value.get.return_value = []
        mock_coll.return_value = mock_ref

        res = client.post('/register/user', json={
            'username': 'secureuser',
            'password': 'superSecretPassword123'
        })
        assert res.status_code == 200
        assert res.get_json()['success'] is True

        called_dict = mock_ref.add.call_args[0][0]
        assert 'password' not in called_dict
        assert 'password_hash' in called_dict
        expected_hash = hashlib.sha256('superSecretPassword123'.encode()).hexdigest()
        assert called_dict['password_hash'] == expected_hash


def test_registration_requires_existing_account(client):
    """Verify registration fails if the user account does not already exist (no silent phantom creation)."""
    future_date = datetime.now(timezone.utc) + timedelta(days=2)
    mock_event = MagicMock()
    mock_event.exists = True
    mock_event.to_dict.return_value = {'name': 'E', 'date': future_date}

    with patch.object(even.db, 'collection') as mock_coll:
        def collection_router(name):
            mock_ref = MagicMock()
            if name == 'events':
                mock_ref.document.return_value.get.return_value = mock_event
            elif name == 'users':
                # No such user exists
                mock_ref.where.return_value.limit.return_value.get.return_value = []
            return mock_ref

        mock_coll.side_effect = collection_router

        res = client.post('/api/events/evt-1/register', json={'username': 'phantom_user'})
        assert res.status_code == 404
        assert 'user not found' in res.get_json()['error'].lower()


def test_get_users_strips_passwords(admin_client):
    """Verify that GET /api/users never exposes password or password_hash fields."""
    mock_u1 = MagicMock()
    mock_u1.id = 'u1'
    mock_u1.to_dict.return_value = {
        'username': 'alice',
        'email': 'alice@example.com',
        'role': 'user',
        'status': 'active',
        'password': 'plaintext_secret_123',
        'password_hash': 'sha256_hash_value'
    }

    with patch.object(even.db, 'collection') as mock_coll:
        mock_ref = MagicMock()
        mock_ref.stream.return_value = [mock_u1]
        mock_coll.return_value = mock_ref

        res = admin_client.get('/api/users')
        assert res.status_code == 200
        users = res.get_json()['users']
        assert len(users) == 1
        assert 'password' not in users[0]
        assert 'password_hash' not in users[0]
        assert users[0]['username'] == 'alice'


def test_duplicate_event_name_rejected(admin_client):
    """Verify creating an event with a duplicate name is rejected."""
    mock_existing_event = MagicMock()

    with patch.object(even.db, 'collection') as mock_coll:
        mock_ref = MagicMock()
        mock_ref.where.return_value.limit.return_value.get.return_value = [mock_existing_event]
        mock_coll.return_value = mock_ref

        res = admin_client.post('/api/events', json={
            'name': 'Existing Event',
            'date': '2026-11-01T10:00:00Z',
            'location': 'Hall 1',
            'description': 'Duplicate test'
        })
        assert res.status_code == 200
        assert res.get_json()['success'] is False
        assert 'already exists' in res.get_json()['error'].lower()


# ============================================================================
# Firebase Initialization & Configuration Tests
# ============================================================================
def test_init_firebase_missing_credentials_raises_file_not_found():
    """Verify init_firebase raises FileNotFoundError with clear message when file is missing."""
    with pytest.raises(FileNotFoundError) as exc_info:
        even.init_firebase(cred_path='/nonexistent/custom-key-file.json')
    assert "not found at" in str(exc_info.value)
    assert "FIREBASE_CREDENTIALS_PATH" in str(exc_info.value)


def test_init_firebase_invalid_credentials_raises_value_error(tmp_path):
    """Verify init_firebase raises ValueError when credentials file is malformed or invalid."""
    bad_cred_file = tmp_path / "invalid-key.json"
    bad_cred_file.write_text("{\"project_id\": \"corrupted\", \"private_key\": \"bad\"}", encoding="utf-8")
    with pytest.raises(ValueError) as exc_info:
        even.init_firebase(cred_path=str(bad_cred_file))
    assert "Failed to initialize Firebase using credentials" in str(exc_info.value)


def test_init_firebase_custom_client_injection():
    """Verify init_firebase accepts and registers a mock client via dependency injection."""
    custom_mock = MagicMock(name='CustomInjectedClient')
    res = even.init_firebase(client=custom_mock)
    assert res is custom_mock
    assert even.db is custom_mock


def test_uninitialized_db_access_returns_500(client):
    """Verify that when db is None and credentials are absent, requests return a 500 error cleanly."""
    even.db = None
    with patch('os.path.exists', return_value=False):
        res = client.get('/api/events')
        assert res.status_code == 500
        data = res.get_json()
        assert data['success'] is False
        assert 'Database service unavailable' in data['error']
