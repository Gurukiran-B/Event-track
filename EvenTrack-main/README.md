# EventTrack

EventTrack is a Flask and Google Cloud Firestore (Firebase) event management platform providing administrative event scheduling, user management, and public attendee registration with automated event lifecycle enforcement.

---

## Table of Contents
- [Project Overview & Verified Features](#project-overview--verified-features)
- [Technology Stack](#technology-stack)
- [Project Directory Structure](#project-directory-structure)
- [Local Installation & Setup](#local-installation--setup)
- [Firebase Credential Configuration](#firebase-credential-configuration)
- [Environment Variables](#environment-variables)
- [Running the Application](#running-the-application)
- [Authentication, Authorization & Security Architecture](#authentication-authorization--security-architecture)
- [Event Expiry & Registration Lifecycle](#event-expiry--registration-lifecycle)
- [Automated Tests & Verification](#automated-tests--verification)
- [Troubleshooting](#troubleshooting)
- [Deployment Precautions](#deployment-precautions)
- [Licensing Status](#licensing-status)
- [Future Improvements](#future-improvements)

---

## Project Overview & Verified Features

EventTrack provides an API-driven event management workflow:

1. **Event Management (Admin)**: Create, view, update, and soft-delete events with duplicate-name prevention and strict field validation.
2. **Event Lifecycle & Expiry**:
   - Active upcoming events appear in the active management list and attendee catalog.
   - Ended events automatically transition to an archive state without database record deletion.
   - Past events remain accessible via an admin **Past / Archived Events** view for audit history.
3. **Attendee Registration**:
   - Users browse upcoming events and register with an existing username.
   - Registration is rejected on expired events on both frontend and backend.
   - Direct backend API requests cannot bypass registration closure.
4. **Attendee Privacy & IDOR Prevention**:
   - Non-admin visitors querying registrations receive masked usernames (e.g., `jo***`), preventing participant list harvesting.
   - Administrators see full participant usernames and registration timestamps.
5. **User Management (Admin)**: View all registered users, update account status and roles, and delete accounts. Passwords are never returned in user listings.
6. **Application Settings (Admin)**: Manage UI preferences (theme, dark mode, default view, events per page) with server-side key allowlisting.
7. **Responsive Interface**: All administrative and user interfaces adapt cleanly across mobile (`< 768px`), tablet, and desktop viewports.

---

## Technology Stack

- **Backend Framework**: Python 3.10+ / Flask 3.0.3
- **Database**: Google Firebase Cloud Firestore (NoSQL) via `firebase-admin` 6.5.0
- **Cross-Origin Handling**: `flask-cors` 4.0.1
- **Environment Management**: `python-dotenv` 1.0.0
- **Testing**: `pytest` 8.2+ / 9.1+
- **Frontend**: HTML5, Vanilla CSS3, JavaScript (Fetch API)

---

## Project Directory Structure

```text
Event-track/
├── .gitignore                      # Top-level Git ignore (secrets, caches, virtualenvs)
├── README.md                       # Root repository summary
└── EvenTrack-main/
    ├── even.py                     # Main Flask application and REST API endpoints
    ├── README.md                   # Application documentation
    ├── requirements.txt            # Python dependencies
    ├── templates/                  # Frontend HTML templates
    │   ├── admin.html              # Legacy admin template
    │   ├── admin_dashboard.html    # Admin event and user management dashboard
    │   ├── event.html              # Landing portal (Admin/User login & registration)
    │   ├── settings.html           # Admin configuration and preferences
    │   ├── user.html               # Dedicated attendee login and registration portal
    │   ├── user_events.html        # Attendee event discovery and registration portal
    │   └── users.html              # Admin user management view
    └── tests/
        └── test_eventtrack.py      # Automated PyTest test suite (21 test cases)
```

---

## Local Installation & Setup

### Prerequisites
- Python 3.10 or higher (tested on Python 3.14)
- Git

### Windows PowerShell

```powershell
# Navigate to application directory
cd D:\Event-track-push\EvenTrack-main

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Git Bash / Linux / macOS

```bash
# Navigate to application directory
cd EvenTrack-main

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # On Windows Git Bash: source .venv/Scripts/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Firebase Credential Configuration

EventTrack uses the Google Cloud Firestore server SDK (`firebase-admin`). It requires a service account JSON credentials file.

### Step-by-Step Setup
1. Log in to the [Firebase Console](https://console.firebase.google.com/).
2. Select or create your Firebase project with Cloud Firestore enabled.
3. Navigate to **Project Settings** (gear icon) > **Service Accounts**.
4. Click **Generate new private key** and confirm to download the JSON credentials.
5. Place the downloaded JSON file inside the `EvenTrack-main/` directory named:
   ```text
   firebase-service-account-key.json
   ```
   *Alternatively*, you may place the file elsewhere and set the `FIREBASE_CREDENTIALS_PATH` environment variable pointing to its absolute path.

> [!WARNING]
> **Credential Security**: Never commit `firebase-service-account-key.json` to version control. It provides administrative access to your Cloud Firestore database. The file is listed in `.gitignore`. Note that `.gitignore` only prevents untracked files from being staged; if credentials were ever committed previously in Git history, `.gitignore` does not remove them from history.

---

## Environment Variables

EventTrack supports the following configuration environment variables:

| Variable | Description | Default Value | Confirmed in Code |
|:---|:---|:---|:---:|
| `SECRET_KEY` | Secret key used to cryptographically sign Flask session cookies. | `dev-secret-change-in-production` | Yes (`even.py:12`) |
| `ALLOWED_ORIGIN` | Allowed origin for CORS headers. | `http://localhost:5000` | Yes (`even.py:15`) |
| `FLASK_DEBUG` | Enables Flask interactive debug mode (`true` or `false`). | `false` | Yes (`even.py:768`) |
| `FIREBASE_CREDENTIALS_PATH` | Explicit path to the Firebase service account JSON key. | `firebase-service-account-key.json` | Yes (`even.py:47`) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Standard Google Cloud credentials path fallback. | None | Yes (`even.py:48`) |

### Setting Environment Variables Example

**PowerShell:**
```powershell
$env:SECRET_KEY = "your-custom-production-secret-key"
$env:FLASK_DEBUG = "false"
$env:FIREBASE_CREDENTIALS_PATH = "C:\secure\firebase-service-account-key.json"
```

**Bash:**
```bash
export SECRET_KEY="your-custom-production-secret-key"
export FLASK_DEBUG="false"
export FIREBASE_CREDENTIALS_PATH="/secure/firebase-service-account-key.json"
```

---

## Running the Application

Make sure your virtual environment is active and Firebase credentials are in place:

```bash
python even.py
```

The application will start on `http://127.0.0.1:5000`.

### Accessible Endpoints
- **Portal Landing / Login**: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- **Attendee Events Portal**: [http://127.0.0.1:5000/user/events](http://127.0.0.1:5000/user/events)
- **Admin Event Management**: [http://127.0.0.1:5000/admin](http://127.0.0.1:5000/admin)
- **Admin Settings**: [http://127.0.0.1:5000/settings](http://127.0.0.1:5000/settings)
- **Admin User Management**: [http://127.0.0.1:5000/users](http://127.0.0.1:5000/users)

---

## Authentication, Authorization & Security Architecture

### Role-Based Access Control
- **Session Authentication**: Handled via signed Flask session cookies (`session['admin_logged_in']` and `session['user_logged_in']`).
- **Authorization Guard**: The `@require_admin_session` decorator protects:
  - `POST /api/events` (Create event)
  - `PUT /api/events/<event_id>` (Update event)
  - `DELETE /api/events/<event_id>` (Delete event)
  - `GET /api/users` (List users without passwords)
  - `POST /api/users` (Create user account)
  - `PUT /api/users/<user_id>` (Update user account)
  - `DELETE /api/users/<user_id>` (Delete user account)
  - `GET /api/settings` and `POST /api/settings` (Read/write settings)
- Unauthenticated or regular user requests to these endpoints return HTTP `401 Unauthorized`.

### Server-Side Input Validation
- Event names, locations, and descriptions are trimmed and validated via `_safe_str()`. Empty or whitespace-only inputs are rejected with HTTP `400 Bad Request`.
- Event name uniqueness is enforced on both creation and renaming.
- Settings updates enforce an explicit key allowlist (`theme`, `darkMode`, `defaultView`, `eventsPerPage`, `notifications`, `emailNotifications`, `emailAddress`). Unrecognized fields are stripped.

### Known Security Limitations & Migration Requirements
1. **Password Storage (SHA-256)**:
   - Passwords currently use standard SHA-256 hashing (`hashlib.sha256`).
   - Plain SHA-256 is a fast cryptographic digest without salt or configurable work factor; it is **not** a secure long-term password-hashing algorithm and is vulnerable to GPU-based dictionary and rainbow table attacks.
   - **Required Migration**: Migrate password storage to a dedicated, salted algorithm such as `bcrypt`, `argon2id`, or official Firebase Authentication prior to production deployment.
2. **Cloud Firestore Security Rules**:
   - The backend accesses Firestore using a privileged server-side service account via `firebase-admin`, which bypasses Firestore Security Rules.
   - If client-side Firebase libraries or public web API keys are ever added to frontend templates, production Firestore Security Rules must be independently verified in the Firebase Console to prevent public database access.
3. **CSRF Tokens**:
   - Session authentication uses cookies without explicit CSRF tokens on HTML forms. State-changing operations currently rely on JSON payloads and same-origin CORS restrictions.

---

## Event Expiry & Registration Lifecycle

### Timezone Strategy
- The application's configured local timezone is **Asia/Kolkata (IST = UTC+5:30)** (`IST` defined in `even.py`).
- Dates entered in naive format (e.g., from `<input type="datetime-local">`) are interpreted as IST and stored normalized in UTC.
- Event expiry is evaluated against current UTC time:
  $$\text{Expired} \iff \text{event\_datetime} < \text{datetime.now}(\text{timezone.utc})$$

### Lifecycle Behavior
- **Active Listing**: `GET /api/events` returns only non-expired events by default.
- **Archive Listing**: `GET /api/events?include_expired=true` returns both active and expired events with an `expired` boolean flag.
- **Frontend State**: Expired events display a **Registration Closed** status badge and have their registration buttons disabled (`aria-disabled="true"`).
- **Backend Lockout**: `POST /api/events/<event_id>/register` evaluates `_event_is_expired(event_data)`. Requests on expired events are rejected with HTTP `400 Bad Request`:
  ```json
  {"success": false, "error": "Registration is closed — this event has ended"}
  ```
- **Data Preservation**: Expiry does not delete events or registration documents from Cloud Firestore. Historical records remain intact for reporting.

---

## Automated Tests & Verification

EventTrack includes an automated test suite in `EvenTrack-main/tests/test_eventtrack.py`.

### Running Tests

```bash
# From EvenTrack-main/ directory
pytest tests/ -v

# Or from the repository root
pytest EvenTrack-main/tests/ -v
```

### Verified Test Results (21/21 Passing)
Tests run with an isolated Firestore mock fixture without requiring a production Firebase key and without touching live database collections:

1. `test_unauthenticated_cannot_access_admin_operations` — All admin endpoints return 401 when unauthenticated.
2. `test_regular_user_cannot_perform_admin_operations` — Regular user sessions cannot access admin endpoints.
3. `test_user_registration_privacy` — Unauthenticated visitors receive masked attendee names (`jo***`).
4. `test_invalid_event_input_is_rejected` — Missing/empty fields and malformed dates return 400.
5. `test_registration_succeeds_before_deadline` — Valid registrations on future events succeed.
6. `test_registration_rejected_at_or_after_deadline` — Registrations on past events return 400.
7. `test_direct_backend_request_cannot_bypass_closed_registration` — Direct API POST requests on expired events fail.
8. `test_ended_events_disappear_from_active_list` — `GET /api/events` excludes ended events.
9. `test_expiry_does_not_destroy_history_or_records` — Expired events retain fields and data intact.
10. `test_date_parsing_and_timezone` — Verifies UTC and Asia/Kolkata (IST) date conversions.
11. `test_settings_allowed_keys_validation` — Unallowed keys in settings updates are stripped.
12. `test_all_html_pages_render` — All 6 application HTML routes return HTTP 200 with responsive viewport meta tags.
13. `test_auth_status_and_logout` — Tests `/api/auth-status` and session invalidation on `/logout`.
14. `test_password_hashing_security` — Verifies passwords are not stored in plaintext.
15. `test_registration_requires_existing_account` — Phantom user auto-creation is prevented.
16. `test_get_users_strips_passwords` — Passwords are removed from user listings.
17. `test_duplicate_event_name_rejected` — Duplicate event names return error.
18. `test_init_firebase_missing_credentials_raises_file_not_found` — Missing credentials raise clear `FileNotFoundError`.
19. `test_init_firebase_invalid_credentials_raises_value_error` — Corrupted credentials raise `ValueError`.
20. `test_init_firebase_custom_client_injection` — Verifies dependency injection of mock clients.
21. `test_uninitialized_db_access_returns_500` — Database requests without initialized credentials return HTTP 500 cleanly.

---

## Troubleshooting

### 1. Missing Firebase Credentials on Startup
- **Symptom**: `[FATAL STARTUP ERROR] Firebase service account credentials not found at...`
- **Cause**: The application cannot find `firebase-service-account-key.json`.
- **Solution**: Download your service account key from Firebase Console and place it in `EvenTrack-main/` or export `FIREBASE_CREDENTIALS_PATH="/path/to/key.json"`.

### 2. Port Already in Use (Port 5000)
- **Symptom**: `OSError: [Errno 10048] error while attempting to bind on address ('0.0.0.0', 5000)`
- **Solution**: Stop any running Flask process or check the process holding port 5000:
  ```powershell
  # Windows PowerShell
  netstat -ano | findstr 5000
  Stop-Process -Id <PID> -Force
  ```

### 3. Template or File Not Found Errors
- **Symptom**: `jinja2.exceptions.TemplateNotFound: event.html`
- **Cause**: Running `python even.py` from outside the `EvenTrack-main/` directory.
- **Solution**: Always `cd EvenTrack-main` before executing `python even.py`.

### 4. PowerShell Script Execution Policy
- **Symptom**: `Activate.ps1 cannot be loaded because running scripts is disabled on this system.`
- **Solution**: Run PowerShell as Administrator and execute:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

---

## Deployment Precautions

1. **WSGI Server**: Do not run the built-in Flask development server (`python even.py`) in production. Use a production WSGI server:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 even:app
   ```
   On Windows servers, use `waitress`:
   ```bash
   pip install waitress
   waitress-serve --port=5000 even:app
   ```
2. **Reverse Proxy & HTTPS**: Run behind Nginx or an Application Load Balancer with TLS termination.
3. **Secret Key**: Set a cryptographically secure, high-entropy `SECRET_KEY` in production environment variables.

---

## Licensing Status

The repository currently does not include a standalone `LICENSE` file. Confirm license terms with the repository owner before redistributing or using this codebase in commercial applications.

---

## Future Improvements

- [ ] **Modern Password Hashing**: Migrate from SHA-256 to `argon2id` or `bcrypt`.
- [ ] **Official Firebase Auth SDK**: Integrate Firebase Authentication for Google/GitHub OAuth2 sign-in.
- [ ] **CSRF Protection**: Add `Flask-WTF` CSRF tokens for state-changing browser requests.
- [ ] **Rate Limiting**: Add `Flask-Limiter` to mitigate brute-force attacks on `/login/*` and `/register/*`.
- [ ] **Containerization**: Provide a production-ready `Dockerfile` and `docker-compose.yml`.
