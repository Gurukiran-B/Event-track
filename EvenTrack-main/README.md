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

1. **Event Management (Admin)**: Create, view, update, and delete events with duplicate-name prevention and strict field validation.
2. **Event Lifecycle & Expiry**:
   - Active upcoming events appear in the active management list and attendee catalog.
   - Ended events automatically transition to an archive state without database record deletion.
   - Past events remain accessible via an admin **Past / Archived Events** view for audit history.
3. **Attendee Registration**:
   - Logged-in users browse upcoming events and register as the identity held in their session.
   - Registration is rejected on expired events on both frontend and backend.
   - Anonymous requests cannot register or choose another user's identity.
4. **Attendee Privacy & IDOR Prevention**:
   - Only administrators can view paginated attendee names and timestamps.
   - Logged-in users can see only whether they personally registered; anonymous visitors cannot query registrations.
5. **User Management (Admin)**: View paginated registered users, create accounts with initial passwords, update account status and roles, and delete accounts. Passwords are never returned in user listings. Accounts assigned the `admin` role authenticate through the admin login; deactivation or demotion invalidates their session on the next protected request.
6. **Application Settings (Admin)**: Manage UI preferences (theme, dark mode, default view, events per page) with server-side key allowlisting.
7. **Responsive Interface**: All administrative and user interfaces adapt cleanly across mobile (`< 768px`), tablet, and desktop viewports.

---

## Technology Stack

- **Backend Framework**: Python 3.10+ / Flask 3.0.3
- **Database**: Google Firebase Cloud Firestore (NoSQL) via `firebase-admin` 6.5.0
- **Cross-Origin Handling**: `flask-cors` 4.0.1
- **Rate Limiting**: Flask-Limiter 3.12 with shared Redis storage for multi-worker deployments
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
        └── test_eventtrack.py      # Automated PyTest test suite
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
$env:SECRET_KEY = (& python -c "import secrets; print(secrets.token_hex(32))")
$env:RATELIMIT_STORAGE_URI = "memory://"
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
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export RATELIMIT_STORAGE_URI="memory://"
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
| `SECRET_KEY` | Secret key used to cryptographically sign Flask session cookies; must contain at least 32 characters. | Required | Yes |
| `ALLOWED_ORIGIN` | Allowed origin for CORS headers. | `http://localhost:5000` | Yes |
| `FLASK_DEBUG` | Enables Flask interactive debug mode (`true` or `false`). | `false` | Yes |
| `SESSION_COOKIE_SECURE` | Adds the Secure attribute to session cookies; enable behind HTTPS. | `false` | Yes |
| `RATELIMIT_STORAGE_URI` | Flask-Limiter backend URI. Use `memory://` only for local single-process development; use shared Redis in production. | Required | Yes |
| `TRUSTED_PROXY_COUNT` | Number of trusted reverse-proxy hops used to restore client IP for rate limits. Only set when direct public access to Flask is blocked. | `0` | Yes |
| `FIREBASE_CREDENTIALS_PATH` | Explicit path to the Firebase service account JSON key. | `firebase-service-account-key.json` | Yes |
| `GOOGLE_APPLICATION_CREDENTIALS` | Standard Google Cloud credentials path fallback. | None | Yes |

### Setting Environment Variables Example

**PowerShell:**
```powershell
$env:SECRET_KEY = (& python -c "import secrets; print(secrets.token_hex(32))")
$env:FLASK_DEBUG = "false"
$env:SESSION_COOKIE_SECURE = "false" # Set to true when serving over HTTPS.
$env:RATELIMIT_STORAGE_URI = "memory://" # Local, single-process use only.
$env:FIREBASE_CREDENTIALS_PATH = "C:\secure\firebase-service-account-key.json"
```

**Bash:**
```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export FLASK_DEBUG="false"
export SESSION_COOKIE_SECURE="true" # Use false only for local HTTP development.
export RATELIMIT_STORAGE_URI="rediss://user:password@redis.example.com:6379/0"
export FIREBASE_CREDENTIALS_PATH="/secure/firebase-service-account-key.json"
```

---

## Running the Application

Make sure your virtual environment is active, a 32-character-or-longer `SECRET_KEY`, `RATELIMIT_STORAGE_URI`, and Firebase credentials are configured:

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
- Admin accounts cannot be created publicly; `POST /register/admin` requires an authenticated administrator. Provision the initial administrator through a trusted operator-controlled process.
- Session cookies are HttpOnly and SameSite=Lax. Set `SESSION_COOKIE_SECURE=true` when HTTPS is enabled; the application refuses to start if `SECRET_KEY` is missing or shorter than 32 characters.
- Every state-changing request must include the session-bound `X-CSRF-Token`. Rendered pages supply a token and their same-origin `fetch` requests add the header. Direct API clients must first render a page or request `GET /api/csrf-token`, retain the session cookie, and send that token on each `POST`, `PUT`, `PATCH`, or `DELETE`.
- Login is limited to 5 attempts per minute and 30 per hour per client IP; public user signup to 5 per hour; admin/user provisioning to 10 per hour. All rate limits use the configured storage backend. `memory://` is process-local and only suitable for local development; production workers must share a Redis-compatible service. Keep Redis credentials out of source control and use TLS where supported.
- If deployed behind a reverse proxy, set `TRUSTED_PROXY_COUNT` only to the exact number of trusted proxy hops and block direct access to the Flask server. Otherwise, leave it at `0` and do not trust forwarded headers.
- To bootstrap the first administrator, use a trusted operator workstation to create an `admins` Firestore document containing `username` and a Werkzeug password hash. Generate the hash with `python -c "from getpass import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass()))"`. Do not place the plaintext password or service-account key in source control.
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
- Admin-created user records require an initial password. A `user` role logs in through `/login/user`; an `admin` role logs in through `/login/admin`. Existing legacy admin accounts in the separate `admins` collection continue to authenticate there.

### Server-Side Input Validation
- Event names, locations, and descriptions are trimmed and validated via `_safe_str()`. Empty or whitespace-only inputs are rejected with HTTP `400 Bad Request`.
- Event name uniqueness is enforced on both creation and renaming.
- New usernames use deterministic account IDs plus username-reservation documents, written atomically. Event names use reservation documents committed atomically with event creation/rename/deletion. Registrations use a deterministic `(event_id, username)` document ID. Existing random-ID accounts, events, and registrations are checked before writes and are not destructively migrated.
- Event listings, admin user listings, and admin registration details are paginated (default 50 items, maximum 100) and return `next_cursor`; the interfaces provide a “Load more” control.
- Settings updates enforce an explicit key allowlist (`theme`, `darkMode`, `defaultView`, `eventsPerPage`, `notifications`, `emailNotifications`, `emailAddress`). Unrecognized fields are stripped.

### Known Security Limitations & Migration Requirements
1. **Legacy Password Migration**:
   - New passwords use Werkzeug's salted, work-factor-based password hash.
   - Existing SHA-256 hashes and plaintext password fields are accepted only to complete a successful login, then upgraded to a new hash and the plaintext field is deleted.
   - Rotate any credentials that may have been exposed and monitor old accounts for successful migration.
2. **Cloud Firestore Security Rules**:
   - The backend accesses Firestore using a privileged server-side service account via `firebase-admin`, which bypasses Firestore Security Rules.
   - If client-side Firebase libraries or public web API keys are ever added to frontend templates, production Firestore Security Rules must be independently verified in the Firebase Console to prevent public database access.
3. **CSRF Tokens**:
   - State-changing requests require a session-bound CSRF token. Browser clients use the token rendered into same-origin pages; direct clients must retain and send it with the session cookie.

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

Tests run with an isolated Firestore mock fixture; they do not require production Firebase credentials and do not access live collections. Coverage includes:

- Authentication, role enforcement, admin-created account login, deactivation, and legacy password migration.
- CSRF rejection/acceptance and login, registration, and admin-provisioning rate limits.
- Race-safe duplicate handling for event names, usernames, and event registrations.
- Event/user pagination, registration privacy, event expiry and timezone behavior.
- Firebase initialization, user-list password stripping, settings allowlisting, and HTML template rendering.

Use the test command above for the current pass count; do not rely on a manually maintained historical test total.

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

- [ ] **Official Firebase Auth SDK**: Integrate Firebase Authentication for Google/GitHub OAuth2 sign-in.
- [ ] **Containerization**: Provide a production-ready `Dockerfile` and `docker-compose.yml`.
