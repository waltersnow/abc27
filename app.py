from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import secrets
import functools
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

app = Flask(__name__)
# 配置 SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///contacts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# 使用环境变量中的密钥，如果没有则生成一个
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))
# 配置 session
app.config['SESSION_COOKIE_SECURE'] = False  # 允许 HTTP
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1小时
app.config['SESSION_COOKIE_DOMAIN'] = os.getenv('SESSION_COOKIE_DOMAIN', None)  # 根据环境设置

# 允许的域名
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:8080,http://127.0.0.1:8080,http://abc27.cn').split(',')

# 配置 CORS
CORS(app, 
    supports_credentials=True,
    resources={
        r"/api/*": {
            "origins": ALLOWED_ORIGINS,
            "methods": ["GET", "POST", "OPTIONS", "DELETE", "PUT"],
            "allow_headers": ["Content-Type"],
            "expose_headers": ["Access-Control-Allow-Origin"],
            "supports_credentials": True
        }
    }
)

db = SQLAlchemy(app)

# 定义数据模型
class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    country_code = db.Column(db.String(10), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    submit_time = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 创建数据库表
with app.app_context():
    db.create_all()
    # 创建默认管理员账户
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

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
    
    user = User.query.filter_by(username=username).first()
    
    if user and user.check_password(password):
        session.permanent = True  # 设置为永久 session
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

        # 创建新联系人
        new_contact = Contact(
            name=name,
            country_code=country_code,
            phone=phone
        )
        db.session.add(new_contact)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '提交成功'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'提交联系人失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'服务器错误: {str(e)}'
        }), 500

@app.route('/api/contacts', methods=['GET'])
@login_required
def get_contacts():
    try:
        contacts = Contact.query.order_by(Contact.submit_time.desc()).all()
        contact_list = [{
            'id': c.id,
            'name': c.name,
            'country_code': c.country_code,
            'phone': c.phone,
            'submit_time': c.submit_time.isoformat()
        } for c in contacts]

        return jsonify({
            'success': True,
            'contacts': contact_list
        })

    except Exception as e:
        app.logger.error(f'获取联系人列表失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'查询错误: {str(e)}'
        }), 500

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    try:
        users = User.query.order_by(User.created_at.desc()).all()
        user_list = [{
            'id': u.id,
            'username': u.username,
            'created_at': u.created_at.isoformat()
        } for u in users]

        return jsonify({
            'success': True,
            'users': user_list
        })

    except Exception as e:
        app.logger.error(f'获取用户列表失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'查询错误: {str(e)}'
        }), 500

@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'success': False, 'message': '用户名和密码不能为空'}), 400

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': '用户名已存在'}), 400

        # 创建新用户
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '用户创建成功'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'创建用户失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'创建用户失败: {str(e)}'
        }), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404

        if user.username == 'admin':
            return jsonify({'success': False, 'message': '不能删除管理员账户'}), 403

        db.session.delete(user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '用户删除成功'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'删除用户失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'删除用户失败: {str(e)}'
        }), 500

@app.route('/api/users/<int:user_id>/password', methods=['PUT'])
@login_required
def change_password(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'message': '用户不存在'}), 404

        data = request.json
        new_password = data.get('password')
        if not new_password:
            return jsonify({'success': False, 'message': '新密码不能为空'}), 400

        user.set_password(new_password)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '密码修改成功'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'修改密码失败: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'修改密码失败: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)