import os
import sys
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from werkzeug.security import check_password_hash, generate_password_hash
from google.api_core.exceptions import AlreadyExists

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-testing-with-32-chars')
os.environ.setdefault('RATELIMIT_STORAGE_URI', 'memory://')

import even
from even import app, _parse_event_date, _event_is_expired, _serialize_event, IST, init_firebase

# Inject a mock Firestore client so tests are completely independent of production credentials
_mock_firestore = MagicMock(name='MockFirestoreClient')
init_firebase(client=_mock_firestore)


def _new_client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key-for-testing'
    app.config['RATELIMIT_ENABLED'] = False
    client = app.test_client()
    token_response = client.get('/api/csrf-token')
    client.environ_base['HTTP_X_CSRF_TOKEN'] = token_response.get_json()['csrf_token']
    return client


@pytest.fixture(autouse=True)
def reset_mock_db():
    """Ensure even.db is always restored to _mock_firestore before and after each test."""
    even.db = _mock_firestore
    _mock_firestore.batch.reset_mock(return_value=True, side_effect=True)
    yield
    even.db = _mock_firestore
    _mock_firestore.batch.reset_mock(return_value=True, side_effect=True)


@pytest.fixture
def client():
    return _new_client()


@pytest.fixture
def admin_client():
    c = _new_client()
    with c.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['username'] = 'testadmin'
    return c


@pytest.fixture
def user_client():
    c = _new_client()
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


def test_csrf_token_is_required_for_state_changes():
    missing_token_client = app.test_client()
    with missing_token_client.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['username'] = 'testadmin'

    response = missing_token_client.post('/api/settings', json={'theme': 'dark'})
    assert response.status_code == 403
    assert response.get_json()['error'] == 'CSRF validation failed'


def test_csrf_token_from_page_session_allows_admin_mutation(admin_client):
    with patch.object(even.db, 'collection') as mock_coll:
        response = admin_client.post('/api/settings', json={'theme': 'blue'})

    assert response.status_code == 200
    assert response.get_json()['success'] is True
    mock_coll.assert_called_once_with('settings')


def test_login_rate_limit_is_enforced(client):
    app.config['RATELIMIT_ENABLED'] = True
    even.limiter.reset()
    try:
        with patch.object(even.db, 'collection') as mock_coll:
            mock_coll.return_value.where.return_value.limit.return_value.get.return_value = []
            responses = [
                client.post('/login/user', json={'username': 'nobody', 'password': 'wrong-password'})
                for _ in range(6)
            ]
        assert all(response.status_code == 200 for response in responses[:5])
        assert responses[5].status_code == 429
        assert responses[5].is_json
    finally:
        app.config['RATELIMIT_ENABLED'] = False
        even.limiter.reset()


def test_registration_rate_limit_is_enforced(client):
    app.config['RATELIMIT_ENABLED'] = True
    even.limiter.reset()
    try:
        with patch.object(even.db, 'collection') as mock_coll:
            users_ref = MagicMock()
            users_ref.where.return_value.limit.return_value.get.return_value = []
            mock_coll.return_value = users_ref
            responses = [
                client.post('/register/user', json={
                    'username': f'ratelimit-user-{index}',
                    'password': 'valid-password'
                })
                for index in range(6)
            ]
        assert all(response.status_code == 200 for response in responses[:5])
        assert responses[5].status_code == 429
    finally:
        app.config['RATELIMIT_ENABLED'] = False
        even.limiter.reset()


def test_admin_provisioning_rate_limit_is_enforced(admin_client):
    app.config['RATELIMIT_ENABLED'] = True
    even.limiter.reset()
    try:
        with patch.object(even.db, 'collection') as mock_coll:
            admins_ref = MagicMock()
            admins_ref.where.return_value.limit.return_value.get.return_value = []
            mock_coll.return_value = admins_ref
            responses = [
                admin_client.post('/register/admin', json={
                    'username': f'provisioned-admin-{index}',
                    'password': 'valid-password'
                })
                for index in range(11)
            ]
        assert all(response.status_code == 200 for response in responses[:10])
        assert responses[10].status_code == 429
    finally:
        app.config['RATELIMIT_ENABLED'] = False
        even.limiter.reset()


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
def test_registration_details_are_admin_only_and_users_see_only_their_status(client, user_client, admin_client):
    """Anonymous visitors see no registration data; users see only their status; admins see details."""
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
        mock_reg_ref.where.return_value.order_by.return_value.limit.return_value.stream.return_value = [
            mock_reg1, mock_reg2
        ]
        mock_reg_ref.where.return_value.where.return_value.limit.return_value.get.return_value = [mock_reg2]

        # 1. Unauthenticated visitor: participant data is unavailable
        res_anon = client.get('/api/events/evt1/registrations')
        assert res_anon.status_code == 401
        assert user_client.get('/api/events/evt1/registrations').status_code == 401

        # 2. Regular user: receives only a boolean for their own registration.
        status_user = user_client.get('/api/events/evt1/registration')
        assert status_user.get_json() == {'registered': True}

        # 3. Admin: sees paginated registration details.
        res_admin = admin_client.get('/api/events/evt1/registrations')
        data_admin = res_admin.get_json()
        assert [entry['username'] for entry in data_admin['registrations']] == ['john_doe', 'regularuser']


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
def test_registration_succeeds_before_deadline(user_client):
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
    mock_user_doc.to_dict.return_value = {'username': 'regularuser', 'status': 'active'}

    with patch.object(even.db, 'collection') as mock_coll:
        references = {}

        def collection_side_effect(name):
            mock_ref = MagicMock()
            references[name] = mock_ref
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

        res = user_client.post('/api/events/evt-future/register', json={'username': 'attacker'})
        assert res.status_code == 200
        assert res.get_json()['success'] is True
        registered_data = references['registrations'].document.return_value.create.call_args[0][0]
        registered_doc_id = references['registrations'].document.call_args[0][0]
        assert registered_data['username'] == 'regularuser'
        assert registered_doc_id == even._stable_document_id(
            'evt-future', 'regularuser'
        )


def test_registration_rejected_at_or_after_deadline(user_client):
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

        res = user_client.post('/api/events/evt-past/register', json={'username': 'attendee1'})
        assert res.status_code == 400
        assert res.get_json()['success'] is False
        assert 'registration is closed' in res.get_json()['error'].lower()


def test_concurrent_duplicate_registration_returns_conflict(user_client):
    event_doc = MagicMock()
    event_doc.exists = True
    event_doc.to_dict.return_value = {
        'name': 'Future Event',
        'date': datetime.now(timezone.utc) + timedelta(days=5)
    }
    user_doc = MagicMock()
    user_doc.to_dict.return_value = {'status': 'active'}

    with patch.object(even.db, 'collection') as mock_coll:
        references = {}

        def collection(name):
            ref = MagicMock()
            references[name] = ref
            if name == 'events':
                ref.document.return_value.get.return_value = event_doc
            elif name == 'users':
                ref.where.return_value.limit.return_value.get.return_value = [user_doc]
            elif name == 'registrations':
                ref.where.return_value.where.return_value.limit.return_value.get.return_value = []
                ref.document.return_value.create.side_effect = AlreadyExists('duplicate registration')
            return ref

        mock_coll.side_effect = collection
        response = user_client.post('/api/events/evt-future/register', json={})

    assert response.status_code == 409
    assert 'already registered' in response.get_json()['error'].lower()


def test_direct_backend_request_cannot_bypass_closed_registration(client):
    """Anonymous API requests cannot register or bypass the closed-registration rule."""
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

        # Direct HTTP POST without a logged-in user session
        res = client.post('/api/events/evt-closed/register', json={'username': 'direct_api_hacker'})
        assert res.status_code == 401


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
        mock_ref.order_by.return_value.limit.return_value.stream.return_value = [past_event, active_event]
        mock_coll.return_value = mock_ref

        # 1. Default request: only active event returned
        res_default = client.get('/api/events')
        data_default = res_default.get_json()
        assert len(data_default['events']) == 1
        assert data_default['events'][0]['id'] == 'active1'
        assert data_default['events'][0]['expired'] is False

        # 2. Request with include_expired=true: both returned with correct status
        res_all = client.get('/api/events?include_expired=true')
        data_all = res_all.get_json()['events']
        assert len(data_all) == 2
        past_found = next(e for e in data_all if e['id'] == 'past1')
        active_found = next(e for e in data_all if e['id'] == 'active1')
        assert past_found['expired'] is True
        assert active_found['expired'] is False


def test_events_api_limits_pages_and_returns_cursor(client):
    first = MagicMock()
    first.id = 'event-one'
    first.to_dict.return_value = {
        'name': 'Event One',
        'date': datetime.now(timezone.utc) + timedelta(days=1)
    }
    second = MagicMock()
    second.id = 'event-two'
    second.to_dict.return_value = {
        'name': 'Event Two',
        'date': datetime.now(timezone.utc) + timedelta(days=2)
    }

    with patch.object(even.db, 'collection') as mock_coll:
        mock_ref = MagicMock()
        mock_ref.order_by.return_value.limit.return_value.stream.return_value = [first, second]
        mock_coll.return_value = mock_ref

        response = client.get('/api/events?limit=1')

    assert response.status_code == 200
    payload = response.get_json()
    assert [event['id'] for event in payload['events']] == ['event-one']
    assert payload['next_cursor'] == 'event-one'
    mock_ref.order_by.return_value.limit.assert_called_once_with(2)


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
        assert 'name="csrf-token"' in html, f"CSRF token missing from {page}"


def test_templates_escape_dynamic_event_and_user_content():
    template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
    expected_escaped_values = {
        'admin.html': ('${escapeHtml(event.name)}', '${escapeHtml(event.location)}',
                       '${escapeHtml(event.description)}'),
        'admin_dashboard.html': ('${escapeHtml(event.name)}', '${escapeHtml(event.location)}',
                                 '${escapeHtml(event.description)}',
                                 "${escapeHtml(user.username || 'N/A')}"),
        'user_events.html': ('${escapeHtml(event.name)}', '${escapeHtml(event.location)}',
                             '${escapeHtml(event.description)}'),
        'users.html': ("${escapeHtml(user.username || 'N/A')}",
                       "${escapeHtml(user.email || 'N/A')}"),
    }

    for template_name, escaped_values in expected_escaped_values.items():
        with open(os.path.join(template_dir, template_name), encoding='utf-8') as template_file:
            template = template_file.read()
        for escaped_value in escaped_values:
            assert escaped_value in template


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
    assert client.get('/logout').status_code == 405


# ============================================================================
# Additional Security & Integrity Tests
# ============================================================================
def test_password_hashing_security(client):
    """Verify that passwords use Werkzeug's salted password hash and are not stored in plaintext."""
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

        called_dict = even.db.batch.return_value.create.call_args_list[-1].args[1]
        assert 'password' not in called_dict
        assert 'password_hash' in called_dict
        assert called_dict['password_hash'] != 'superSecretPassword123'
        assert check_password_hash(called_dict['password_hash'], 'superSecretPassword123')


def test_legacy_sha256_password_is_upgraded_after_login(client):
    """A valid legacy SHA-256 login upgrades the stored value without breaking the account."""
    import hashlib

    account = MagicMock()
    account.to_dict.return_value = {
        'username': 'legacyuser',
        'status': 'active',
        'password_hash': hashlib.sha256(b'legacy-password').hexdigest()
    }

    with patch.object(even.db, 'collection') as mock_coll:
        mock_coll.return_value.where.return_value.limit.return_value.get.return_value = [account]

        response = client.post('/login/user', json={
            'username': 'legacyuser',
            'password': 'legacy-password'
        })

    assert response.status_code == 200
    assert response.get_json()['success'] is True
    upgraded_hash = account.reference.update.call_args[0][0]['password_hash']
    assert check_password_hash(upgraded_hash, 'legacy-password')
    assert upgraded_hash != account.to_dict.return_value['password_hash']


def test_legacy_plaintext_password_is_upgraded_after_login(client):
    """A valid legacy plaintext login is upgraded and the plaintext field is deleted."""
    account = MagicMock()
    account.to_dict.return_value = {
        'username': 'plaintextuser',
        'status': 'active',
        'password': 'legacy-password'
    }

    with patch.object(even.db, 'collection') as mock_coll:
        mock_coll.return_value.where.return_value.limit.return_value.get.return_value = [account]

        response = client.post('/login/user', json={
            'username': 'plaintextuser',
            'password': 'legacy-password'
        })

    assert response.status_code == 200
    assert response.get_json()['success'] is True
    updates = account.reference.update.call_args[0][0]
    assert check_password_hash(updates['password_hash'], 'legacy-password')
    assert updates['password'] is even.firestore.DELETE_FIELD


def test_inactive_user_cannot_log_in(client):
    account = MagicMock()
    account.to_dict.return_value = {
        'username': 'inactiveuser',
        'status': 'inactive',
        'password_hash': generate_password_hash('valid-password')
    }

    with patch.object(even.db, 'collection') as mock_coll:
        mock_coll.return_value.where.return_value.limit.return_value.get.return_value = [account]

        response = client.post('/login/user', json={
            'username': 'inactiveuser',
            'password': 'valid-password'
        })

    assert response.get_json()['success'] is False
    account.reference.update.assert_not_called()


def test_admin_registration_requires_admin_session(client):
    with patch.object(even.db, 'collection') as mock_coll:
        response = client.post('/register/admin', json={
            'username': 'attacker',
            'password': 'valid-password'
        })

    assert response.status_code == 401
    mock_coll.assert_not_called()


def test_admin_can_provision_another_admin(admin_client):
    with patch.object(even.db, 'collection') as mock_coll:
        mock_ref = MagicMock()
        mock_ref.where.return_value.limit.return_value.get.return_value = []
        mock_coll.return_value = mock_ref

        response = admin_client.post('/register/admin', json={
            'username': 'newadmin',
            'password': 'valid-password'
        })

    assert response.status_code == 200
    stored_account = even.db.batch.return_value.create.call_args_list[-1].args[1]
    assert check_password_hash(stored_account['password_hash'], 'valid-password')


def test_admin_created_user_has_login_credentials(admin_client):
    with patch.object(even.db, 'collection') as mock_coll:
        users_ref = MagicMock()
        users_ref.where.return_value.limit.return_value.get.return_value = []
        users_ref.document.return_value.id = 'created-user-id'
        mock_coll.return_value = users_ref

        response = admin_client.post('/api/users', json={
            'username': 'staffuser',
            'password': 'valid-password',
            'email': 'staff@example.com',
            'role': 'user',
            'status': 'active'
        })

    assert response.status_code == 200
    stored_account = even.db.batch.return_value.create.call_args_list[-1].args[1]
    assert stored_account['role'] == 'user'
    assert check_password_hash(stored_account['password_hash'], 'valid-password')


def test_admin_created_admin_role_authenticates_against_user_account(admin_client):
    with patch.object(even.db, 'collection') as mock_coll:
        users_ref = MagicMock()
        users_ref.where.return_value.limit.return_value.get.return_value = []
        users_ref.document.return_value.id = 'managed-admin-id'
        mock_coll.return_value = users_ref

        response = admin_client.post('/api/users', json={
            'username': 'created-admin',
            'password': 'valid-password',
            'role': 'admin',
            'status': 'active'
        })

    assert response.status_code == 200
    account = even.db.batch.return_value.create.call_args_list[-1].args[1]
    assert account['role'] == 'admin'
    assert check_password_hash(account['password_hash'], 'valid-password')


def test_admin_created_admin_role_can_log_in_as_admin(client):
    account = MagicMock()
    account.id = 'managed-admin-id'
    account.to_dict.return_value = {
        'username': 'managedadmin',
        'password_hash': generate_password_hash('valid-password'),
        'role': 'admin',
        'status': 'active'
    }

    with patch.object(even.db, 'collection') as mock_coll:
        admins_ref = MagicMock()
        admins_ref.where.return_value.limit.return_value.get.return_value = []
        users_query = MagicMock()
        users_query.where.return_value.limit.return_value.get.return_value = [account]
        users_ref = MagicMock()
        users_ref.where.return_value = users_query

        def collection(name):
            return admins_ref if name == 'admins' else users_ref

        mock_coll.side_effect = collection
        response = client.post('/login/admin', json={
            'username': 'managedadmin',
            'password': 'valid-password'
        })

    assert response.status_code == 200
    assert response.get_json()['success'] is True
    assert client.get('/api/auth-status').get_json()['role'] == 'admin'


def test_inactive_admin_created_user_session_is_revoked(client):
    account = MagicMock()
    account.exists = True
    account.to_dict.return_value = {'role': 'user', 'status': 'inactive'}
    with client.session_transaction() as sess:
        sess['admin_logged_in'] = True
        sess['admin_account_source'] = 'users'
        sess['admin_account_id'] = 'managed-admin-id'
        sess['username'] = 'managedadmin'

    with patch.object(even.db, 'collection') as mock_coll:
        mock_coll.return_value.document.return_value.get.return_value = account
        response = client.get('/api/users')

    assert response.status_code == 401
    assert response.get_json()['error'] == 'Unauthorized: Admin account is inactive'
    assert client.get('/api/auth-status').get_json()['logged_in'] is False


def test_admin_role_account_cannot_log_in_as_regular_user(client):
    account = MagicMock()
    account.to_dict.return_value = {
        'username': 'managedadmin',
        'password_hash': generate_password_hash('valid-password'),
        'role': 'admin',
        'status': 'active'
    }
    with patch.object(even.db, 'collection') as mock_coll:
        mock_coll.return_value.where.return_value.limit.return_value.get.return_value = [account]
        response = client.post('/login/user', json={
            'username': 'managedadmin',
            'password': 'valid-password'
        })

    assert response.get_json()['success'] is False
    assert client.get('/api/auth-status').get_json()['logged_in'] is False


def test_registration_requires_existing_account(user_client):
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

        res = user_client.post('/api/events/evt-1/register', json={'username': 'phantom_user'})
        assert res.status_code == 401
        assert 'account is unavailable' in res.get_json()['error'].lower()


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
        mock_ref.order_by.return_value.limit.return_value.stream.return_value = [mock_u1]
        mock_coll.return_value = mock_ref

        res = admin_client.get('/api/users')
        assert res.status_code == 200
        users = res.get_json()['users']
        assert len(users) == 1
        assert 'password' not in users[0]
        assert 'password_hash' not in users[0]
        assert users[0]['username'] == 'alice'


def test_user_list_is_paginated(admin_client):
    first = MagicMock()
    first.id = 'user-one'
    first.to_dict.return_value = {'username': 'alice', 'password_hash': 'not-returned'}
    second = MagicMock()
    second.id = 'user-two'
    second.to_dict.return_value = {'username': 'bob'}

    with patch.object(even.db, 'collection') as mock_coll:
        users_ref = MagicMock()
        users_ref.order_by.return_value.limit.return_value.stream.return_value = [first, second]
        mock_coll.return_value = users_ref

        response = admin_client.get('/api/users?limit=1')

    assert response.status_code == 200
    payload = response.get_json()
    assert [user['username'] for user in payload['users']] == ['alice']
    assert 'password_hash' not in payload['users'][0]
    assert payload['next_cursor'] == 'user-one'


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
        assert res.status_code == 409
        assert res.get_json()['success'] is False
        assert 'already exists' in res.get_json()['error'].lower()


def test_event_name_reservation_conflict_is_atomic(admin_client):
    with patch.object(even.db, 'collection') as mock_coll:
        events_ref = MagicMock()
        events_ref.where.return_value.limit.return_value.get.return_value = []
        events_ref.document.return_value.id = 'new-event-id'
        mock_coll.return_value = events_ref
        even.db.batch.return_value.commit.side_effect = AlreadyExists('event name claimed')

        response = admin_client.post('/api/events', json={
            'name': 'Concurrent Event',
            'date': '2026-11-01T10:00:00Z',
            'location': 'Hall 1',
            'description': 'Concurrent create test'
        })

    assert response.status_code == 409
    assert 'already exists' in response.get_json()['error'].lower()


def test_username_reservation_conflict_is_atomic(client):
    with patch.object(even.db, 'collection') as mock_coll:
        users_ref = MagicMock()
        users_ref.where.return_value.limit.return_value.get.return_value = []
        mock_coll.return_value = users_ref
        even.db.batch.return_value.commit.side_effect = AlreadyExists('username claimed')

        response = client.post('/register/user', json={
            'username': 'concurrent-user',
            'password': 'valid-password'
        })

    assert response.status_code == 409
    assert 'username already exists' in response.get_json()['message'].lower()


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
