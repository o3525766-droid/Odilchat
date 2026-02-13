from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session
from datetime import datetime
import json
import os
import secrets
import hashlib
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Файл для хранения сообщений и пользователей
MESSAGES_FILE = 'messages.json'
USERS_FILE = 'users.json'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['email']
        self.name = user_data['name']
        self.email = user_data['email']
        self.gmail_number = user_data.get('gmail_number', '')
        self.password_hash = user_data.get('password_hash', '')
        self.is_admin = user_data.get('email') == 'o3525766@gmail.com'
        self.created_at = user_data.get('created_at', '')
        self.last_login = user_data.get('last_login', '')

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    user_data = users.get(user_id)
    if user_data:
        return User(user_data)
    return None

def load_users():
    """Загружает пользователей из файла"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Сохраняет пользователей в файл"""
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def extract_gmail_number(email):
    """Извлекает номер из Gmail адреса"""
    username = email.split('@')[0]
    import re
    numbers = re.findall(r'\d+', username)
    if numbers:
        return numbers[0]
    return username

def hash_password(password):
    """Хеширует пароль"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Проверяет пароль"""
    return hash_password(password) == password_hash

def load_messages():
    """Загружает сообщения из файла"""
    if os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_messages(messages):
    """Сохраняет сообщения в файл"""
    with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
        json.dump(messages, f, ensure_ascii=False, indent=2)

@app.route('/')
def index():
    """Главная страница чата"""
    # Проверяем, не вошел ли уже пользователь
    if not current_user.is_authenticated:
        # Автоматически входим как администратор если это специальный случай
        return redirect(url_for('auto_login_admin'))
    return render_template('index.html')

@app.route('/auto_login_admin')
def auto_login_admin():
    """Автоматический вход администратора"""
    admin_email = 'o3525766@gmail.com'
    users = load_users()
    
    # Если администратора нет в системе, создаем его
    if admin_email not in users:
        users[admin_email] = {
            'name': 'Admin',
            'email': admin_email,
            'gmail_number': '3525766',
            'password_hash': hash_password('admin123'), # Стандартный пароль
            'created_at': datetime.now().isoformat()
        }
        save_users(users)
    
    # Входим как администратор
    user = User(users[admin_email])
    login_user(user)
    
    return redirect(url_for('index'))

@app.route('/api/messages', methods=['GET'])
@login_required
def get_messages():
    """Возвращает все сообщения"""
    messages = load_messages()
    return jsonify(messages)

@app.route('/api/send', methods=['POST'])
@login_required
def send_message():
    """Отправляет новое сообщение"""
    data = request.get_json()
    
    if not data or 'message' not in data:
        return jsonify({'error': 'Missing message'}), 400
    
    message = data['message'].strip()
    
    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    # Создаем новое сообщение с данными текущего пользователя
    new_message = {
        'id': len(load_messages()) + 1,
        'username': current_user.name,
        'gmail_number': current_user.gmail_number,
        'email': current_user.email,
        'message': message,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }
    
    # Загружаем текущие сообщения, добавляем новое и сохраняем
    messages = load_messages()
    messages.append(new_message)
    save_messages(messages)
    
    return jsonify(new_message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    # Если пользователь уже вошел, перенаправляем в чат
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            return render_template('login.html', error='Заполните все поля')
        
        users = load_users()
        user_data = users.get(email)
        
        if user_data and verify_password(password, user_data['password_hash']):
            user = User(user_data)
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Неверный email или пароль')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Страница регистрации"""
    # Если пользователь уже вошел, перенаправляем в чат
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not name or not email or not password:
            return render_template('register.html', error='Заполните все поля')
        
        if password != confirm_password:
            return render_template('register.html', error='Пароли не совпадают')
        
        if len(password) < 6:
            return render_template('register.html', error='Пароль должен быть не менее 6 символов')
        
        users = load_users()
        
        if email in users:
            return render_template('register.html', error='Пользователь с таким email уже существует')
        
        # Создаем нового пользователя
        gmail_number = extract_gmail_number(email)
        users[email] = {
            'name': name,
            'email': email,
            'gmail_number': gmail_number,
            'password_hash': hash_password(password),
            'created_at': datetime.now().isoformat()
        }
        
        save_users(users)
        
        # Автоматически входим после регистрации
        user = User(users[email])
        login_user(user)
        
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/admin')
@login_required
def admin_panel():
    """Панель администратора"""
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    users = load_users()
    messages = load_messages()
    
    # Статистика
    total_users = len(users)
    total_messages = len(messages)
    online_users = len([u for u in users.values() if u.get('last_login')])
    
    return render_template('admin.html', 
                      users=users, 
                      messages=messages,
                      total_users=total_users,
                      total_messages=total_messages,
                      online_users=online_users)

@app.route('/admin/delete_user/<email>', methods=['POST'])
@login_required
def delete_user(email):
    """Удаление пользователя"""
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    if email == 'o3525766@gmail.com':
        return jsonify({'error': 'Cannot delete admin account'}), 400
    
    users = load_users()
    if email in users:
        del users[email]
        save_users(users)
        return jsonify({'success': True})
    
    return jsonify({'error': 'User not found'}), 404

@app.route('/admin/clear_user_messages/<email>', methods=['POST'])
@login_required
def clear_user_messages(email):
    """Очистка сообщений пользователя"""
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    messages = load_messages()
    messages = [msg for msg in messages if msg.get('email') != email]
    save_messages(messages)
    
    return jsonify({'success': True})

@app.route('/logout')
def logout():
    """Выход из системы"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/robots.txt')
def robots():
    """Обслуживает robots.txt для поисковых систем"""
    return send_from_directory('static', 'robots.txt')

@app.route('/api/clear', methods=['POST'])
@login_required
def clear_messages():
    """Очищает все сообщения"""
    save_messages([])
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
