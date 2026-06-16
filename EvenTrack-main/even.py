from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ----------------------------
# Firebase Setup
# ----------------------------
cred = credentials.Certificate(os.path.join(os.path.dirname(__file__), 'firebase-service-account-key.json'))
firebase_admin.initialize_app(cred)
db = firestore.client()

# ----------------------------
# API ROUTES
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

@app.route('/register/user', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    print(f"[DEBUG] Registering user: {username}")
    try:
        users_ref = db.collection('users')
        query = users_ref.where('username', '==', username).limit(1)
        if len(query.get()) > 0:
            print(f"[DEBUG] Username already exists: {username}")
            return jsonify({'success': False, 'message': 'Username already exists'})
        user_data = {
            'username': username,
            'password': password,
            'email': f"{username}@example.com",
            'role': 'user',
            'status': 'active',
            'lastLogin': firestore.SERVER_TIMESTAMP,
            'created_at': firestore.SERVER_TIMESTAMP
        }
        users_ref.add(user_data)
        print(f"[DEBUG] User registered: {username}")
        return jsonify({'success': True, 'message': 'User registered successfully'})
    except Exception as e:
        print(f"[ERROR] Registration failed for {username}: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/register/admin', methods=['POST'])
def register_admin():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    try:
        # Check if admin already exists
        admins_ref = db.collection('admins')
        query = admins_ref.where('username', '==', username).limit(1)
        if len(query.get()) > 0:
            return jsonify({'success': False, 'message': 'Username already exists'})

        # Add new admin
        admins_ref.add({
            'username': username,
            'password': password,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Admin registered successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/login/user', methods=['POST'])
def login_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    try:
        users_ref = db.collection('users')
        query = users_ref.where('username', '==', username).where('password', '==', password).limit(1)
        user = query.get()
        return jsonify({'success': len(user) > 0})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/login/admin', methods=['POST'])
def login_admin():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    try:
        admins_ref = db.collection('admins')
        query = admins_ref.where('username', '==', username).where('password', '==', password).limit(1)
        admin = query.get()
        return jsonify({'success': len(admin) > 0})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# ----------------------------
# Event Management Routes
# ----------------------------

@app.route('/admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/api/events', methods=['GET'])
def get_events():
    try:
        events_ref = db.collection('events')
        events = events_ref.order_by('date', direction=firestore.Query.DESCENDING).stream()
        return jsonify([{**event.to_dict(), 'id': event.id} for event in events])
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/events', methods=['POST'])
def create_event():
    data = request.json
    try:
        events_ref = db.collection('events')
        
        # Check for duplicate event name
        query = events_ref.where('name', '==', data['name']).limit(1)
        if len(query.get()) > 0:
            return jsonify({'success': False, 'error': 'Event with this name already exists'})
            
        event_data = {
            'name': data['name'],
            'date': datetime.fromisoformat(data['date'].replace('Z', '+00:00')),
            'location': data['location'],
            'description': data['description'],
            'created_at': firestore.SERVER_TIMESTAMP
        }
        doc_ref = events_ref.add(event_data)
        return jsonify({'success': True, 'id': doc_ref[1].id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/events/<event_id>', methods=['PUT'])
def update_event(event_id):
    data = request.json
    try:
        events_ref = db.collection('events')
        
        # Check for duplicate event name
        query = events_ref.where('name', '==', data['name']).stream()
        for doc in query:
            if doc.id != event_id:
                return jsonify({'success': False, 'error': 'Another event with this name already exists'})
                
        event_ref = events_ref.document(event_id)
        
        # Handle date conversion
        date_str = data['date']
        try:
            # Try parsing as ISO format first
            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except ValueError:
            try:
                # Try parsing as datetime-local format (YYYY-MM-DDThh:mm)
                date_obj = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
            except ValueError:
                # Try parsing as date format (YYYY-MM-DD)
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        
        event_data = {
            'name': data['name'],
            'date': date_obj,
            'location': data['location'],
            'description': data['description'],
            'updated_at': firestore.SERVER_TIMESTAMP
        }
        event_ref.update(event_data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/events/<event_id>', methods=['DELETE'])
def delete_event(event_id):
    try:
        db.collection('events').document(event_id).delete()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/users')
def users():
    return render_template('users.html')

@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        users_ref = db.collection('users')
        users = users_ref.stream()
        user_list = []
        for user in users:
            user_data = user.to_dict()
            user_data['id'] = user.id
            user_list.append(user_data)
        print(f"[DEBUG] Users fetched: {len(user_list)}")
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        print(f"[ERROR] Fetching users failed: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    try:
        users_ref = db.collection('users')
        user_data = {
            'username': data['username'],
            'email': data['email'],
            'role': data['role'],
            'status': data['status'],
            'lastLogin': firestore.SERVER_TIMESTAMP,
            'created_at': firestore.SERVER_TIMESTAMP
        }
        doc_ref = users_ref.add(user_data)
        return jsonify({'success': True, 'id': doc_ref[1].id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    try:
        user_ref = db.collection('users').document(user_id)
        user_data = {
            'username': data['username'],
            'email': data['email'],
            'role': data['role'],
            'status': data['status'],
            'updated_at': firestore.SERVER_TIMESTAMP
        }
        user_ref.update(user_data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        db.collection('users').document(user_id).delete()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/settings', methods=['GET'])
def get_settings():
    try:
        settings_ref = db.collection('settings').document('app_settings')
        settings = settings_ref.get()
        if settings.exists:
            return jsonify(settings.to_dict())
        return jsonify({
            'theme': 'blue',
            'darkMode': False,
            'defaultView': 'grid',
            'eventsPerPage': 12,
            'notifications': True,
            'emailNotifications': False
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/settings', methods=['POST'])
def update_settings():
    data = request.json
    try:
        settings_ref = db.collection('settings').document('app_settings')
        settings_ref.set(data, merge=True)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/events/<event_id>/register', methods=['POST'])
def register_for_event(event_id):
    data = request.json
    username = data.get('username')
    if not username:
        return jsonify({'success': False, 'error': 'Username is required'}), 400
    try:
        # Check if user exists, if not create one
        users_ref = db.collection('users')
        user_query = users_ref.where('username', '==', username).limit(1)
        user_docs = user_query.get()
        
        if len(user_docs) == 0:
            # Create new user
            user_data = {
                'username': username,
                'email': f"{username}@example.com",  # Default email
                'role': 'user',
                'status': 'active',
                'lastLogin': firestore.SERVER_TIMESTAMP,
                'created_at': firestore.SERVER_TIMESTAMP
            }
            users_ref.add(user_data)

        # Check if already registered
        reg_ref = db.collection('registrations')
        query = reg_ref.where('event_id', '==', event_id).where('username', '==', username).limit(1)
        if len(query.get()) > 0:
            return jsonify({'success': False, 'error': 'Already registered for this event'})
        
        # Add registration
        reg_ref.add({
            'event_id': event_id,
            'username': username,
            'registered_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({'success': True, 'message': 'Registered successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/events/<event_id>/registrations', methods=['GET'])
def get_event_registrations(event_id):
    try:
        reg_ref = db.collection('registrations')
        registrations = reg_ref.where('event_id', '==', event_id).stream()
        return jsonify([{**reg.to_dict(), 'id': reg.id} for reg in registrations])
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Try to fetch a document from Firestore
        db.collection('users').limit(1).get()
        return jsonify({'success': True, 'message': 'Firestore connection OK'})
    except Exception as e:
        print(f"[ERROR] Firestore health check failed: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/events/<event_id>', methods=['GET'])
def get_event(event_id):
    try:
        event_ref = db.collection('events').document(event_id)
        event = event_ref.get()
        if event.exists:
            event_data = event.to_dict()
            event_data['id'] = event.id
            # Convert Firestore timestamp to ISO string if present
            if 'date' in event_data and hasattr(event_data['date'], 'isoformat'):
                event_data['date'] = event_data['date'].isoformat()
            return jsonify(event_data)
        else:
            return jsonify({'success': False, 'error': 'Event not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ----------------------------
# Run the server
# ----------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
