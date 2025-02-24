from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import sqlite3
from datetime import datetime
import hashlib
import secrets
import functools

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # 用于session加密
CORS(app, 
    supports_credentials=True,
    resources={
        r"/api/*": {
            "origins": ["http://localhost:8080", "http://127.0.0.1:8080"],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"],
            "expose_headers": ["Access-Control-Allow-Origin"],
            "supports_credentials": True
        }
    }
)

# 创建数据库和表
def init_db():
    conn = sqlite3.connect('contacts.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            country_code TEXT NOT NULL,
            phone TEXT NOT NULL,
            submit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# 创建默认管理员账户
def create_default_admin():
    conn = sqlite3.connect('contacts.db')
    c = conn.cursor()
    
    # 检查是否已存在管理员账户
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        # 创建默认管理员账户 (用户名: admin, 密码: admin123)
        password = 'admin123'
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                 ('admin', password_hash))
        conn.commit()
    conn.close()

create_default_admin()

# 登录验证装饰器
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'success': False, 'message': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated_function

# 登录接口
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': '用户名和密码不能为空'}), 400
    
    conn = sqlite3.connect('contacts.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if user and user[2] == hashlib.sha256(password.encode()).hexdigest():
        session['logged_in'] = True
        session['username'] = username
        return jsonify({'success': True, 'message': '登录成功'})
    
    return jsonify({'success': False, 'message': '用户名或密码错误'}), 401

# 登出接口
@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True, 'message': '已登出'})

# 获取当前登录状态
@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    return jsonify({
        'success': True,
        'logged_in': session.get('logged_in', False),
        'username': session.get('username', None)
    })

@app.route('/api/submit-contact', methods=['POST'])
def submit_contact():
    try:
        data = request.json
        name = data.get('name')
        country_code = data.get('countryCode')
        phone = data.get('phone')

        # 数据验证
        if not all([name, country_code, phone]):
            return jsonify({'success': False, 'message': '所有字段都是必填的'}), 400

        # 保存到数据库
        conn = sqlite3.connect('contacts.db')
        c = conn.cursor()
        c.execute('''
            INSERT INTO contacts (name, country_code, phone)
            VALUES (?, ?, ?)
        ''', (name, country_code, phone))
        conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': '提交成功'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'服务器错误: {str(e)}'
        }), 500

@app.route('/api/contacts', methods=['GET'])
@login_required
def get_contacts():
    try:
        conn = sqlite3.connect('contacts.db')
        c = conn.cursor()
        c.execute('SELECT * FROM contacts ORDER BY submit_time DESC')
        contacts = c.fetchall()
        conn.close()

        # 将查询结果转换为字典列表
        contact_list = []
        for contact in contacts:
            contact_list.append({
                'id': contact[0],
                'name': contact[1],
                'country_code': contact[2],
                'phone': contact[3],
                'submit_time': contact[4]
            })

        return jsonify({
            'success': True,
            'contacts': contact_list
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'查询错误: {str(e)}'
        }), 500

# 获取用户列表
@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    try:
        conn = sqlite3.connect('contacts.db')
        c = conn.cursor()
        c.execute('SELECT id, username, created_at FROM users ORDER BY created_at DESC')
        users = c.fetchall()
        conn.close()

        user_list = []
        for user in users:
            user_list.append({
                'id': user[0],
                'username': user[1],
                'created_at': user[2]
            })

        return jsonify({
            'success': True,
            'users': user_list
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'查询错误: {str(e)}'
        }), 500

# 添加新用户
@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'success': False, 'message': '用户名和密码不能为空'}), 400
        
        conn = sqlite3.connect('contacts.db')
        c = conn.cursor()
        
        # 检查用户名是否已存在
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': '用户名已存在'}), 400
        
        # 创建新用户
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                 (username, password_hash))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': '用户创建成功'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'创建用户失败: {str(e)}'
        }), 500

# 删除用户
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    try:
        # 不允许删除自己
        if session.get('username') == 'admin':
            conn = sqlite3.connect('contacts.db')
            c = conn.cursor()
            
            # 检查是否是管理员账号
            c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            if user and user[0] == 'admin':
                conn.close()
                return jsonify({'success': False, 'message': '不能删除管理员账号'}), 400
            
            c.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': '用户删除成功'
            })
        else:
            return jsonify({'success': False, 'message': '只有管理员可以删除用户'}), 403

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'删除用户失败: {str(e)}'
        }), 500

# 修改用户密码
@app.route('/api/users/<int:user_id>/password', methods=['PUT'])
@login_required
def change_password(user_id):
    try:
        data = request.json
        new_password = data.get('password')
        
        if not new_password:
            return jsonify({'success': False, 'message': '新密码不能为空'}), 400
        
        conn = sqlite3.connect('contacts.db')
        c = conn.cursor()
        
        # 只允许管理员或用户本人修改密码
        c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        if user and (session.get('username') == 'admin' or session.get('username') == user[0]):
            password_hash = hashlib.sha256(new_password.encode()).hexdigest()
            c.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                     (password_hash, user_id))
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': '密码修改成功'
            })
        else:
            conn.close()
            return jsonify({'success': False, 'message': '没有权限修改此用户的密码'}), 403

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'修改密码失败: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000) 