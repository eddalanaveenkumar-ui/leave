from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import random
import os
import threading
import time
import string
import json

# ── Firebase Admin SDK (for sending push notifications) ──────────────────────
try:
    import firebase_admin
    from firebase_admin import credentials, messaging as fcm_messaging
    _FCM_AVAILABLE = True
except ImportError:
    _FCM_AVAILABLE = False
    print("[WARN] firebase-admin not installed. Push notifications disabled.")
    print("       Run: pip install firebase-admin")


app = Flask(__name__)
CORS(app)

# --- Mock Database Implementation ---
class MockCollection:
    def __init__(self):
        self.data = []
    
    def insert_one(self, doc):
        doc['_id'] = ObjectId()
        self.data.append(doc)
        return type('obj', (object,), {'inserted_id': doc['_id']})
    
    def _get_nested(self, doc, key):
        keys = key.split('.')
        current = doc
        for k in keys:
            if isinstance(current, dict):
                current = current.get(k)
            else:
                return None
        return current

    def find_one(self, query):
        for doc in self.data:
            match = True
            for k, v in query.items():
                if k == '_id' and isinstance(v, ObjectId):
                     if doc.get('_id') != v: match = False
                else:
                    # Support dot notation
                    val = self._get_nested(doc, k)
                    if val != v:
                        match = False
            if match: return doc
        return None

    def find(self, query):
        results = []
        for doc in self.data:
            match = True
            for k, v in query.items():
                if k == '_id': continue 
                
                val = self._get_nested(doc, k)
                if val != v:
                    match = False
            if match: results.append(doc)
        return ConvertCursor(results)
    
    def update_one(self, query, update, upsert=False):
        doc = self.find_one(query)
        if doc:
            if '$set' in update:
                # Basic update (doesn't support deep set yet, but sufficient for now)
                # For updating nested fields via dot notation (e.g. 'details.name'), 
                # we'd need more logic. For this demo, we can assume simple updates 
                # or manually handle the specific structures used in app. 
                # BUT, the current usage in update_user uses dot notation for keys in $set.
                # So we must support setting nested keys too.
                for k, v in update['$set'].items():
                    self._set_nested(doc, k, v)
        elif upsert:
            new_doc = query.copy() # This is shallow, but might be ok for mock
            # Upsert logic usually implies creating based on query
            if '$set' in update:
                 for k, v in update['$set'].items():
                    self._set_nested(new_doc, k, v)
            self.insert_one(new_doc)
            
    def _set_nested(self, doc, key, value):
        keys = key.split('.')
        current = doc
        for i, k in enumerate(keys[:-1]):
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value

    def delete_one(self, query):
        doc = self.find_one(query)
        if doc:
            self.data.remove(doc)

class ConvertCursor:
    def __init__(self, data):
        self.data = data
    def sort(self, key, direction):
        return self.data # No sort in mock
    def __iter__(self):
        return iter(self.data)

class MockDB:
    def __init__(self):
        self.users = MockCollection()
        self.leave_requests = MockCollection()
        self.otps = MockCollection()
        self.fcm_tokens = MockCollection()  # FCM device tokens

# --- MongoDB Setup ---
MONGO_URI = "mongodb+srv://eddalanaveen893_db_user:Naveen1234@triangle.zkuc3ku.mongodb.net/?appName=triangle" 

db = None

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000) # 10s timeout for Atlas
    client.server_info() # Force connection check
    db = client.leave_management_system
    print("Connected to MongoDB Atlas successfully!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    print("--- SWITCHING TO MOCK DATABASE (IN-MEMORY) ---")
    db = MockDB()

# ── Initialize Firebase Admin SDK ─────────────────────────────────────────────
_firebase_initialized = False

def _init_firebase():
    global _firebase_initialized
    if not _FCM_AVAILABLE or _firebase_initialized:
        return
    try:
        # Option 1: Use GOOGLE_APPLICATION_CREDENTIALS env var (production)
        cred_path = os.environ.get('FIREBASE_SERVICE_ACCOUNT_JSON')
        if cred_path and os.path.exists(cred_path):
            cred = credentials.Certificate(cred_path)
        else:
            # Option 2: Inline service account (fallback for dev — keep this file out of git)
            sa_path = os.path.join(os.path.dirname(__file__), 'firebase-service-account.json')
            if os.path.exists(sa_path):
                cred = credentials.Certificate(sa_path)
            else:
                print("[FCM] No service account found. Push notifications disabled.")
                print("[FCM] Provide firebase-service-account.json next to app.py.")
                return
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        _firebase_initialized = True
        print("[FCM] Firebase Admin SDK initialized ✓")
    except Exception as e:
        print(f"[FCM] Firebase init error: {e}")

_init_firebase()

# ── Helper: send push notification via FCM ────────────────────────────────────
def send_push(token: str, title: str, body: str, data: dict = None) -> bool:
    """Send a single push notification to a device token. Returns True on success."""
    if not _firebase_initialized:
        return False
    try:
        msg = fcm_messaging.Message(
            notification=fcm_messaging.Notification(title=title, body=body),
            data={k: str(v) for k, v in (data or {}).items()},
            android=fcm_messaging.AndroidConfig(
                priority='high',
                notification=fcm_messaging.AndroidNotification(
                    sound='default',
                    channel_id=data.get('channel_id', 'leavesync_student') if data else 'leavesync_student',
                    click_action='FLUTTER_NOTIFICATION_CLICK'
                )
            ),
            apns=fcm_messaging.APNSConfig(
                payload=fcm_messaging.APNSPayload(
                    aps=fcm_messaging.Aps(sound='default', badge=1)
                )
            ),
            token=token
        )
        fcm_messaging.send(msg)
        return True
    except Exception as e:
        print(f"[FCM] Send error for token {token[:20]}...: {e}")
        return False

def send_push_to_user(user_id: str, title: str, body: str, data: dict = None):
    """Send push to ALL devices registered for a userId."""
    tokens = list(db.fcm_tokens.find({'userId': user_id}))
    for t in tokens:
        send_push(t['token'], title, body, data)

def send_push_to_role(role: str, title: str, body: str, data: dict = None):
    """Broadcast push to all devices of users with a given role."""
    tokens = list(db.fcm_tokens.find({'role': role}))
    for t in tokens:
        send_push(t['token'], title, body, data)


# --- Helper to serialize MongoDB objects ---
def serialize_doc(doc):
    if not doc: return None
    doc['_id'] = str(doc['_id'])
    return doc

# --- Rotating Admin Credentials ---
ADMIN_CREDS = {"username": "admin", "password": "password"} # Default for fallback
ADMIN_LOG_INTERVAL = 45 

def generate_random_string(length=8):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def rotate_admin_creds():
    while True:
        timestamp = datetime.now().strftime("%H:%M:%S")
        username = f"admin_{generate_random_string(4)}"
        password = generate_random_string(10)
        
        ADMIN_CREDS["username"] = username
        ADMIN_CREDS["password"] = password
        
        print(f"\n[SERVER LOG {timestamp}] --- NEW ADMIN CREDENTIALS GENERATED ---")
        print(f"User ID:  {username}")
        print(f"Password: {password}")
        print(f"Expires in {ADMIN_LOG_INTERVAL} seconds...\n")
        
        time.sleep(ADMIN_LOG_INTERVAL)

if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    admin_thread = threading.Thread(target=rotate_admin_creds, daemon=True)
    admin_thread.start()


# --- API Endpoints ---

# ══════════════════════════════════════════════════════════════════
#  PUSH NOTIFICATION ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.route('/api/save-fcm-token', methods=['POST'])
def save_fcm_token():
    """Called by each app on startup/permission grant to register the device FCM token."""
    try:
        data = request.json
        token   = data.get('token')
        role    = data.get('role', 'student')   # student | staff | parent | admin
        user_id = data.get('userId', '')

        if not token:
            return jsonify({'error': 'Token required'}), 400

        # Upsert: one token entry per device token
        record = {
            'token'    : token,
            'role'     : role,
            'userId'   : str(user_id),
            'updatedAt': datetime.now()
        }

        # Use real MongoDB upsert if available
        try:
            db.fcm_tokens.update_one(
                {'token': token},
                {'$set': record},
                upsert=True
            )
        except AttributeError:
            # MockDB fallback
            existing = db.fcm_tokens.find_one({'token': token})
            if not existing:
                db.fcm_tokens.insert_one(record)

        print(f"[FCM] Token saved for role={role} userId={user_id}")
        return jsonify({'message': 'Token saved', 'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/send-notification', methods=['POST'])
def send_notification():
    """Send push to a specific user by userId OR to all users of a role."""
    try:
        data    = request.json
        title   = data.get('title', 'LeaveSync')
        body    = data.get('body', '')
        user_id = data.get('userId')          # optional: specific user
        role    = data.get('role')             # optional: broadcast to role
        tag     = data.get('tag', 'default')  # approved | rejected | pending | submitted
        url     = data.get('url', '/')

        push_data = {'tag': tag, 'url': url}

        sent = 0
        if user_id:
            tokens = list(db.fcm_tokens.find({'userId': str(user_id)}))
            for t in tokens:
                if send_push(t['token'], title, body, push_data): sent += 1
        elif role:
            tokens = list(db.fcm_tokens.find({'role': role}))
            for t in tokens:
                if send_push(t['token'], title, body, push_data): sent += 1
        else:
            return jsonify({'error': 'Provide userId or role'}), 400

        return jsonify({'message': f'{sent} notification(s) sent', 'sent': sent})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/send-notification/broadcast', methods=['POST'])
def broadcast_notification():
    """Broadcast to ALL registered devices (e.g. system announcements from Admin)."""
    try:
        data  = request.json
        title = data.get('title', 'LeaveSync')
        body  = data.get('body', '')
        tag   = data.get('tag', 'default')

        all_tokens = list(db.fcm_tokens.find({}))
        sent = 0
        for t in all_tokens:
            if send_push(t['token'], title, body, {'tag': tag}): sent += 1

        return jsonify({'message': f'Broadcast sent to {sent} device(s)', 'sent': sent})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --- Login Endpoints ---

@app.route('/api/login/otp', methods=['POST'])
def send_login_otp():
    try:
        data = request.json
        phone = data.get('phone')
        role = data.get('role', 'student') 
        
        if not phone:
            return jsonify({"error": "Phone number required"}), 400

        # DUMMY OTP FOR TESTING
        otp = "123456" 
        
        user = db.users.find_one({"phone": phone, "role": role})
        if not user:
            # Check if they are a student trying to login as something else
            if role in ['management', 'parent', 'mentor', 'hod']:
                 student_check = db.users.find_one({"phone": phone, "role": "student"})
                 if student_check:
                      return jsonify({"error": "You are a Student. Please login via Student Portal."}), 403
            return jsonify({"error": "Account not found. Please contact Admin."}), 404
        
        # User exists, proceed to Firebase
        return jsonify({"message": "User verified", "status": "success"})
    except Exception as e:
        print(f"Login Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/login/verify', methods=['POST'])
def verify_login_otp():
    try:
        data = request.json
        phone = data.get('phone')
        role = data.get('role', 'student') 
        
        user = db.users.find_one({"phone": phone, "role": role})
        
        if user:
            return jsonify({"message": "Login successful", "user": serialize_doc(user)})
        else:
            return jsonify({"error": "Invalid User or Role Mismatch"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Admin Endpoints ---

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    print(f"DEBUG: Admin Login Attempt: '{username}' / '{password}'")
    print(f"DEBUG: Expected Fallback: 'admin' / '1234'")
    
    if (username == ADMIN_CREDS['username'] and password == ADMIN_CREDS['password']) or (username == 'admin' and password == '1234'):
         return jsonify({"message": "Admin Login Successful", "token": "admin-session-token"})
    else:
         print("DEBUG: Credentials Mismatch")
         return jsonify({"error": "Invalid or Expired Credentials"}), 401

@app.route('/api/admin/add_user', methods=['POST'])
def add_user():
    try:
        data = request.json
        role = data.get('role')
        name = data.get('name')
        phone = data.get('phone')
        details = data.get('details', {}) 
        
        if not role or not phone:
            return jsonify({"error": "Missing fields"}), 400

        existing = db.users.find_one({"phone": phone, "role": role})
        if existing:
            return jsonify({"error": "User already exists"}), 400

        # --- VALIDATIONS ---
        # 1. Parent Phone != Student Phone
        if role == 'student':
            p_phone = details.get('parent_phone')
            if p_phone and phone == p_phone:
                return jsonify({"error": "Student phone cannot be the same as Parent phone"}), 400

        # 2. One HOD per Department
        if role == 'hod':
            dept = details.get('dept')
            if dept:
                existing_hod = db.users.find_one({"role": "hod", "details.dept": dept})
                if existing_hod:
                    return jsonify({"error": f"HOD for {dept} already exists ({existing_hod['name']})"}), 400
        # -------------------

        # --- VALIDATIONS ---
        # 1. Parent Phone != Student Phone
        if role == 'student':
            p_phone = details.get('parent_phone')
            if p_phone and phone == p_phone:
                return jsonify({"error": "Student phone cannot be the same as Parent phone"}), 400

        # 2. One HOD per Department
        if role == 'hod':
            dept = details.get('dept')
            if dept:
                existing_hod = db.users.find_one({"role": "hod", "details.dept": dept})
                if existing_hod:
                    return jsonify({"error": f"HOD for {dept} already exists ({existing_hod['name']})"}), 400
        # -------------------
            
        new_user = {
            "role": role,
            "name": name,
            "phone": phone,
            "details": details,
            "created_at": datetime.now()
        }
        
        result = db.users.insert_one(new_user)
        student_id = result.inserted_id

        # Auto-create Parent Account if Student
        if role == 'student':
            p_name = details.get('parent_name')
            p_phone = details.get('parent_phone')
            p_image = details.get('parent_profile_image')
            
            if p_name and p_phone:
                existing_parent = db.users.find_one({"phone": p_phone, "role": "parent"})
                if not existing_parent:
                    db.users.insert_one({
                        "role": "parent",
                        "name": p_name,
                        "phone": p_phone,
                        "details": {"children": [str(student_id)], "profile_image": p_image},
                        "created_at": datetime.now()
                    })
                else:
                    # Append child if not already there checks/logic could go here
                    pass

        return jsonify({"message": f"{role.capitalize()} added successfully", "id": str(student_id)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<role_type>', methods=['GET'])
def get_all_users(role_type):
    try:
        # role_type can be 'student', 'staff' (maps to mentor/hod), 'parent'
        query = {}
        if role_type == 'staff':
            query = {"role": {"$in": ["mentor", "hod", "management"]}}
        else:
            query = {"role": role_type}
            
        users = list(db.users.find(query))
        return jsonify([serialize_doc(u) for u in users])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/update_user', methods=['POST'])
def update_user():
    try:
        data = request.json
        user_id = data.get('user_id')
        updates = data.get('updates')
        
        if not user_id or not updates:
            return jsonify({"error": "Missing user_id or updates"}), 400

        # --- VALIDATIONS FOR UPDATE ---
        current_user = db.users.find_one({"_id": ObjectId(user_id)})
        
        if current_user:
            # 1. Check HOD Uniqueness
            updates_details = updates.get('details', {})
            current_details = current_user.get('details', {}) if current_user.get('details') else {}
            
            new_role = updates.get('role', current_user.get('role'))
            new_dept = updates_details.get('dept')
            if not new_dept: 
                new_dept = current_details.get('dept')
            
            if new_role == 'hod' and new_dept:
                existing_hod = db.users.find_one({"role": "hod", "details.dept": new_dept})
                if existing_hod and str(existing_hod['_id']) != user_id:
                     return jsonify({"error": f"HOD for {new_dept} already exists ({existing_hod['name']})"}), 400
                     
            # 2. Check Parent Phone
            if current_user.get('role') == 'student':
                 new_phone = updates.get('phone', current_user.get('phone'))
                 new_p_phone = updates_details.get('parent_phone')
                 if not new_p_phone:
                      new_p_phone = current_details.get('parent_phone')
                      
                 if new_phone == new_p_phone:
                     return jsonify({"error": "Student phone cannot be the same as Parent phone"}), 400
        # ------------------------------

        # --- VALIDATIONS FOR UPDATE ---
        current_user = db.users.find_one({"_id": ObjectId(user_id)})
        
        # 1. Check HOD Uniqueness if role or dept is changing
        new_role = updates.get('role', current_user.get('role'))
        new_dept = updates.get('details', {}).get('dept', current_user.get('details', {}).get('dept'))
        
        if new_role == 'hod' and new_dept:
            existing_hod = db.users.find_one({"role": "hod", "details.dept": new_dept})
            if existing_hod and str(existing_hod['_id']) != user_id:
                 return jsonify({"error": f"HOD for {new_dept} already exists ({existing_hod['name']})"}), 400
                 
        # 2. Check Parent Phone != Student Phone (if updating student)
        if current_user.get('role') == 'student':
             new_phone = updates.get('phone', current_user.get('phone'))
             new_p_phone = updates.get('details', {}).get('parent_phone', current_user.get('details', {}).get('parent_phone'))
             if new_phone == new_p_phone:
                 return jsonify({"error": "Student phone cannot be the same as Parent phone"}), 400
        # ------------------------------

        # Construct update query
        # We need to map flattened fields back to structure if necessary, or just expect structured updates
        # For simplicity, let's assume 'updates' contains flat keys for name/phone and 'details' dict for the rest
        
        # Prepare updates for the student
        update_fields = {}
        if 'name' in updates: update_fields['name'] = updates['name']
        if 'phone' in updates: update_fields['phone'] = updates['phone']
        if 'role' in updates: update_fields['role'] = updates['role']
        
        # Merge details
        if 'details' in updates:
            for k, v in updates['details'].items():
                update_fields[f'details.{k}'] = v

        # --- SYNC WITH PARENT ACCOUNT ---
        # If updating parent details, we must update the actual Parent User account
        if 'details' in updates and ('parent_phone' in updates['details'] or 'parent_name' in updates['details']):
            try:
                # 1. Get current student data to find OLD parent phone
                student = db.users.find_one({"_id": ObjectId(user_id)})
                if student:
                    old_p_phone = student.get('details', {}).get('parent_phone')
                    
                    # 2. Determine new values
                    new_p_phone = updates['details'].get('parent_phone', old_p_phone)
                    new_p_name = updates['details'].get('parent_name') # Might be undefined if not changing
                    new_p_img = updates['details'].get('parent_profile_image')
                    
                    if old_p_phone:
                        # 3. Find the parent account linked to the OLD phone
                        parent_user = db.users.find_one({"role": "parent", "phone": old_p_phone})
                        
                        # Fallback 1: Search by Child ID (Most reliable if phone is wrong)
                        if not parent_user:
                            parent_user = db.users.find_one({"role": "parent", "details.children": str(user_id)})
                            
                        # Fallback 2: Search by Name (Last resort if link is broken)
                        if not parent_user and updates['details'].get('parent_name'):
                             parent_user = db.users.find_one({"role": "parent", "name": updates['details']['parent_name']})
                        
                        if parent_user:
                            # 4. Prepare updates for the Parent User
                            p_updates = {}
                            if new_p_phone and new_p_phone != old_p_phone:
                                p_updates['phone'] = new_p_phone
                            # Also update phone if the parent currently has the WRONG phone (e.g. dummy or student's phone)
                            if parent_user.get('phone') != new_p_phone:
                                p_updates['phone'] = new_p_phone

                            if 'parent_name' in updates['details']:
                                p_updates['name'] = updates['details']['parent_name']
                            if 'parent_profile_image' in updates['details']:
                                p_updates['details.profile_image'] = updates['details']['parent_profile_image']
                            
                            # Ensure this child is linked
                            current_children = parent_user.get('details', {}).get('children', [])
                            if str(user_id) not in current_children:
                                if 'details.children' not in p_updates: # Don't overwrite if we were doing something else
                                    current_children.append(str(user_id))
                                    p_updates['details.children'] = current_children
                            
                            if p_updates:
                                db.users.update_one({"_id": parent_user['_id']}, {"$set": p_updates})
                                print(f"DEBUG: Synced Parent Account {parent_user['_id']} with new details.")
            except Exception as sync_e:
                print(f"Error syncing parent account: {sync_e}")
        # -------------------------------

        result = db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_fields}
        )
        
        if result.modified_count > 0:
            return jsonify({"message": "User updated successfully"})
        else:
            return jsonify({"message": "No changes made"})
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/staff/search', methods=['GET'])
def search_staff():
    staff_id = request.args.get('staff_id')
    if not staff_id:
        return jsonify({"error": "Staff ID required"}), 400
    
    user = db.users.find_one({"role": {"$ne": "student"}, "details.staff_id": staff_id}) # Staff roles are mentor/hod
    # Fallback to check if role is explicitly stored as staff/mentor/hod
    if not user:
         user = db.users.find_one({"role": {"$in": ["mentor", "hod", "management"]}, "details.staff_id": staff_id})

    if user:
        return jsonify(serialize_doc(user))
    else:
        return jsonify({"error": "Staff not found"}), 404

# --- Core App Endpoints ---

@app.route('/api/student/apply_leave', methods=['POST'])
def apply_leave():
    try:
        data = request.json
        student_id = data.get('student_id')
        reason = data.get('reason')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        leave_request = {
            "student_id": student_id,
            "reason": reason,
            "start_date": start_date,
            "end_date": end_date,
            "status": "pending_parent",
            "parent_approved": False,
            "mentor_approved": False,
            "hod_approved": False,
            "qr_code_data": None,
            "created_at": datetime.now()
        }
        
        result = db.leave_requests.insert_one(leave_request)
        return jsonify({"message": "Leave request submitted", "id": str(result.inserted_id)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/parent/requests', methods=['GET'])
def get_parent_requests():
    requests = list(db.leave_requests.find({"status": "pending_parent"}))
    return jsonify([serialize_doc(r) for r in requests])

@app.route('/api/parent/approve', methods=['POST'])
def parent_approve():
    data   = request.json
    req_id = data.get('request_id')

    db.leave_requests.update_one(
        {'_id': ObjectId(req_id)},
        {'$set': {'status': 'pending_mentor', 'parent_approved': True}}
    )

    # Push to student
    try:
        req = db.leave_requests.find_one({'_id': ObjectId(req_id)})
        if req:
            send_push_to_user(req['student_id'],
                '✅ Parent Approved',
                'Your parent approved your leave. Sent to class advisor.',
                {'tag': 'approved', 'url': '/dashboard.html'})
    except Exception: pass

    return jsonify({'message': 'Approved by Parent. Sent to Mentor.'})

@app.route('/api/mentor/requests', methods=['GET'])
def get_mentor_requests():
    requests = list(db.leave_requests.find({"status": "pending_mentor"}))
    return jsonify([serialize_doc(r) for r in requests])

@app.route('/api/mentor/approve', methods=['POST'])
def mentor_approve():
    data   = request.json
    req_id = data.get('request_id')

    db.leave_requests.update_one(
        {'_id': ObjectId(req_id)},
        {'$set': {'status': 'pending_hod', 'mentor_approved': True}}
    )

    # Push to student
    try:
        req = db.leave_requests.find_one({'_id': ObjectId(req_id)})
        if req:
            send_push_to_user(req['student_id'],
                '⏳ Advisor Approved',
                'Your class advisor approved your leave. Awaiting HOD approval.',
                {'tag': 'pending', 'url': '/dashboard.html'})
    except Exception: pass

    return jsonify({'message': 'Approved by Mentor. Sent to HOD.'})

@app.route('/api/hod/requests', methods=['GET'])
def get_hod_requests():
    requests = list(db.leave_requests.find({"status": "pending_hod"}))
    return jsonify([serialize_doc(r) for r in requests])

@app.route('/api/hod/approve', methods=['POST'])
def hod_approve():
    try:
        data    = request.json
        req_id  = data.get('request_id')
        req     = db.leave_requests.find_one({'_id': ObjectId(req_id)})
        student_id = req.get('student_id')
        student    = db.users.find_one({'_id': ObjectId(student_id)})

        name     = student.get('name') if student else 'Unknown'
        qr_data  = f'APPROVED|{req_id}|{name}'

        db.leave_requests.update_one(
            {'_id': ObjectId(req_id)},
            {'$set': {'status': 'approved', 'hod_approved': True, 'qr_code_data': qr_data}}
        )

        # Push to student — final approval
        send_push_to_user(student_id,
            '✅ Leave Fully Approved!',
            f'HOD approved your leave. Your digital pass is ready.',
            {'tag': 'approved', 'url': '/dashboard.html'})

        # Push to parent — inform them
        try:
            p_phone = student.get('details', {}).get('parent_phone')
            if p_phone:
                parent = db.users.find_one({'phone': p_phone, 'role': 'parent'})
                if parent:
                    send_push_to_user(str(parent['_id']),
                        '✅ Child Leave Approved',
                        f"{name}'s leave has been fully approved by the HOD.",
                        {'tag': 'approved', 'url': '/dashboard.html'})
        except Exception: pass

        return jsonify({'message': 'Approved by HOD. QR Code Generated.'})
    except Exception as e:
        print(f'HOD Approve Error: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/student/delete_request', methods=['POST'])
def delete_request():
    try:
        data = request.json
        req_id = data.get('request_id')
        # Only allow deleting if status is pending_parent (or any pending state if desired)
        # For simplicity, allow delete if not fully approved/rejected
        result = db.leave_requests.delete_one({"_id": ObjectId(req_id)})
        if result.deleted_count > 0:
            return jsonify({"message": "Request deleted successfully"})
        else:
            return jsonify({"error": "Request not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/student/status/<student_id>', methods=['GET'])
def student_status(student_id):
    requests = list(db.leave_requests.find({"student_id": student_id}))
    # Mock sort manually if needed, but list is fine
    return jsonify([serialize_doc(r) for r in requests])

@app.route('/api/student/search', methods=['GET'])
def search_student():
    reg_no = request.args.get('reg_no')
    if not reg_no:
        return jsonify({"error": "Register number required"}), 400
    
    user = db.users.find_one({"role": "student", "details.register_number": reg_no})
    if user:
        return jsonify(serialize_doc(user))
    else:
        return jsonify({"error": "Student not found"}), 404

import pandas as pd

@app.route('/api/admin/bulk_upload', methods=['POST'])
def bulk_upload():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
            
        file = request.files['file']
        user_type = request.form.get('type') # 'student' or 'staff'
        
        if not file.filename:
            return jsonify({"error": "No selected file"}), 400
            
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file, dtype=str)
        elif file.filename.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(file, dtype=str)
        else:
            return jsonify({"error": "Invalid file type. Upload CSV or Excel."}), 400
            
        df.fillna('', inplace=True)
        
        success_count = 0
        errors = []
        
        for index, row in df.iterrows():
            try:
                # Basic validation
                phone = str(row.get('phone', '')).strip()
                name = str(row.get('name', '')).strip()
                
                if not phone or not name:
                    continue
                    
                # Check exist
                existing = db.users.find_one({"phone": phone, "role": user_type})
                if existing:
                    errors.append(f"Row {index+1}: User with phone {phone} already exists")
                    continue

                if user_type == 'student':
                    reg = str(row.get('register_number', '')).strip()
                    dept = str(row.get('department', '')).strip()
                    year = str(row.get('year', '')).strip()
                    p_name = str(row.get('parent_name', '')).strip()
                    p_phone = str(row.get('parent_phone', '')).strip()
                    
                    if p_phone and phone == p_phone:
                        errors.append(f"Row {index+1}: Student phone cannot be same as Parent phone")
                        continue
                    
                    student_data = {
                        "role": "student",
                        "name": name,
                        "phone": phone,
                        "details": {
                            "register_number": reg,
                            "dept": dept,
                            "year": year,
                            "parent_name": p_name,
                            "parent_phone": p_phone,
                            "profile_image": str(row.get('profile_image', '')).strip(),
                            "parent_profile_image": str(row.get('parent_profile_image', '')).strip()
                        },
                        "created_at": datetime.now()
                    }
                    res = db.users.insert_one(student_data)
                    student_id = res.inserted_id
                    
                    # Auto create parent
                    if p_name and p_phone:
                        existing_p = db.users.find_one({"phone": p_phone, "role": "parent"})
                        if not existing_p:
                           db.users.insert_one({
                                "role": "parent",
                                "name": p_name,
                                "phone": p_phone,
                                "details": {
                                    "children": [str(student_id)], 
                                    "profile_image": str(row.get('parent_profile_image', '')).strip()
                                },
                                "created_at": datetime.now()
                           })
                        else:
                             # Add child to existing parent
                             current_children = existing_p.get('details', {}).get('children', [])
                             if str(student_id) not in current_children:
                                 current_children.append(str(student_id))
                                 db.users.update_one(
                                     {"_id": existing_p['_id']}, 
                                     {"$set": {"details.children": current_children}}
                                 )

                elif user_type == 'staff':
                    staff_id = str(row.get('staff_id', '')).strip()
                    role = str(row.get('role', 'mentor')).strip().lower() # Default to mentor
                    dept = str(row.get('department', '')).strip()
                    
                    if role not in ['mentor', 'hod', 'management']:
                        role = 'mentor'
                        
                    if role == 'hod' and dept:
                         existing_hod = db.users.find_one({"role": "hod", "details.dept": dept})
                         if existing_hod:
                             errors.append(f"Row {index+1}: HOD for {dept} already exists ({existing_hod['name']})")
                             continue
                        
                    staff_data = {
                        "role": role,
                        "name": name,
                        "phone": phone,
                        "details": {
                            "staff_id": staff_id,
                            "dept": dept,
                            "profile_image": str(row.get('profile_image', '')).strip()
                        },
                        "created_at": datetime.now()
                    }
                    db.users.insert_one(staff_data)
                
                success_count += 1
                
            except Exception as e:
                errors.append(f"Row {index+1}: {str(e)}")
        
        msg = f"Processed {success_count} users successfully."
        if errors:
            msg += f" {len(errors)} errors occurred: " + "; ".join(errors[:5])
            if len(errors) > 5: msg += "..."
            
        return jsonify({"message": msg, "errors": errors})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
