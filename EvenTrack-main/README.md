# 🚀 EventTrack

EventTrack is a modern, lightweight Event Management Dashboard built using **Python Flask** and **Firebase Firestore**. It provides a seamless interface for event organizers to manage events and for users to browse, register, and track the events they plan to attend. 

Designed with simplicity and scale in mind, EventTrack demonstrates how to effectively integrate cloud-native NoSQL databases (Firebase) with a traditional web framework (Flask) to deliver real-time, persistent event tracking without the overhead of complex SQL relational schemas.

## ✨ Key Features

- **Admin Dashboard**: Easily create, update, and delete upcoming events with a dedicated administrative interface.
- **User Portal**: Allows attendees to sign up, view available events, and seamlessly register.
- **Firebase Firestore Integration**: All data—events, users, and registrations—is securely stored and served via Firebase Cloud Firestore, completely removing local database dependencies.
- **RESTful API Architecture**: The backend acts as a robust API layer for the frontend to consume.
- **Duplicate Prevention**: Backend validation ensures event names remain unique, preventing confusion for attendees.
- **Cross-Origin Resource Sharing (CORS)**: Pre-configured CORS support ensures that frontend interfaces can reliably communicate with the API.

## 🛠 Tech Stack

- **Backend Framework**: Python 3 / Flask
- **Database**: Firebase Cloud Firestore (NoSQL)
- **Frontend**: HTML5, Vanilla CSS, JavaScript (Fetch API)
- **Authentication**: Custom Token / Session flow (Demonstration setup)
- **Deployment & Tooling**: `python-dotenv`, `firebase-admin`, `pip`

## 🏗 Architecture Overview

EventTrack uses a standard Model-View-Controller (MVC) approach adapted for API-driven architectures:
1. **Frontend (View)**: Static HTML/JS templates are rendered by Flask but dynamically fetch their state directly from the API endpoints.
2. **Flask API (Controller)**: `even.py` contains all the routing and logic. It handles payload validation, business logic (e.g., checking for duplicates), and error handling.
3. **Firestore (Model)**: The `firebase-admin` SDK directly communicates with Google Cloud to persist documents in the `events`, `users`, `admins`, and `registrations` collections.

## 📸 Screenshots

| Admin Dashboard | User Portal |
|:---:|:---:|
| ![Admin](https://via.placeholder.com/400x250?text=Admin+Dashboard) | ![User](https://via.placeholder.com/400x250?text=User+Portal) |
*(Add actual screenshots of your application here)*

## 🚀 Installation Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/EventTrack.git
cd EventTrack
```

### 2. Create a Virtual Environment
It is highly recommended to use a virtual environment to manage dependencies:
```bash
python -m venv .venv
# On Windows
.venv\Scripts\activate
# On macOS/Linux
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

## ⚙️ Configuration Setup

### Firebase Setup Requirements
EventTrack uses Firebase Firestore, meaning you must provide a valid Firebase service account key.

1. Go to the [Firebase Console](https://console.firebase.google.com/).
2. Create a new project (or select an existing one).
3. Navigate to **Project Settings > Service Accounts**.
4. Click **Generate new private key** and download the JSON file.
5. Rename the downloaded file to `firebase-service-account-key.json` and place it in the root directory of this project.

## 🏃 Running Locally

Once dependencies are installed and the Firebase JSON key is in place, start the development server:

```bash
python even.py
```

The application will be available at:
- `http://localhost:5000/` or `http://127.0.0.1:5000/`

## 📂 Project Structure

```text
EventTrack/
├── .gitignore                      # Git ignored files & directories
├── even.py                         # Main Flask application and API routes
├── firebase-service-account-key.json # (Ignored) Firebase credentials
├── requirements.txt                # Python dependencies
└── templates/                      # Frontend HTML templates
    ├── admin_dashboard.html
    ├── event.html
    ├── settings.html
    ├── user.html
    ├── user_events.html
    └── users.html
```

## 🔮 Future Enhancements

- **OAuth2 / Firebase Authentication**: Replace custom login logic with official Firebase Auth for Google, GitHub, or Email/Password sign-ins.
- **Frontend Framework Migration**: Transition vanilla HTML/JS to a modern framework like React or Vue.js for improved state management.
- **Dockerization**: Add a `Dockerfile` and `docker-compose.yml` to simplify deployment and environment standardization.
- **Automated Testing**: Implement PyTest suites to guarantee API route stability during upgrades.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
