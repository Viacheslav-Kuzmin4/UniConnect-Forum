from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request, decode_token
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'

# Настройки базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@localhost:5432/messenger'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 360000

# Инициализация расширений
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)

blacklist = set()

@app.before_request
def check_token_in_blacklist():
    token = request.headers.get('Authorization', None)
    if token:
        token = token.split(" ")[1]
        try:
            verify_jwt_in_request()
            decoded_token = get_jwt()
            jti = decoded_token.get('jti')
            if jti in blacklist:
                return jsonify({"description": "The token has been revoked.", "error": "token_revoked"}), 401
        except Exception as e:
            return jsonify({"description": str(e), "error": "invalid_token"}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({"description": "The token has been revoked.", "error": "token_revoked"}), 401

# Модели
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

class Chat(db.Model):
    __tablename__ = 'chats'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'))
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.String, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Схемы
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User

class ChatSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Chat

class MessageSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Message

@app.route('/')
def home():
    return "Welcome to the Messenger API!"

@app.route('/register-page', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash("Все поля обязательны для заполнения.")
            return render_template('register.html')

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Пользователь с таким логином или email уже существует.")
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash("Успешная регистрация. Войдите в систему.")
        return redirect(url_for('login_page'))

    return render_template('register.html')

@app.route('/login-page', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash("Неправильный логин или пароль.")
            return render_template('login.html')

        access_token = create_access_token(identity=user.id)
        session['token'] = access_token
        return redirect(url_for('chats_page'))

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    token = get_jwt()
    jti = token['jti']
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200

@app.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')

    if not check_password_hash(user.password_hash, old_password):
        return jsonify({"error": "Old password is incorrect"}), 400

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({"message": "Password changed successfully"})

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(logged_in_as=user.username)

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    user_schema = UserSchema(many=True)
    return jsonify(user_schema.dump(users))

@app.route('/users/<int:id>', methods=['GET'])
@jwt_required()
def get_user(id):
    user = User.query.get(id)
    if user is None:
        return jsonify({"error": "User not found"}), 404
    user_schema = UserSchema()
    return jsonify(user_schema.dump(user))

@app.route('/chats', methods=['POST'])
@jwt_required()
def add_chat():
    name = request.json.get('name')
    new_chat = Chat(name=name)
    db.session.add(new_chat)
    db.session.commit()
    chat_schema = ChatSchema()
    return jsonify(chat_schema.dump(new_chat)), 201

@app.route('/chats', methods=['GET'])
@jwt_required()
def get_chats():
    chats = Chat.query.all()
    chat_schema = ChatSchema(many=True)
    return jsonify(chat_schema.dump(chats))

@app.route('/chats/<int:chat_id>/messages', methods=['GET'])
@jwt_required()
def get_messages(chat_id):
    messages = Message.query.filter_by(chat_id=chat_id).all()
    message_schema = MessageSchema(many=True)
    return jsonify(message_schema.dump(messages))

@app.route('/messages', methods=['POST'])
@jwt_required()
def add_message():
    chat_id = request.json.get('chat_id')
    sender_id = get_jwt_identity()
    content = request.json.get('content')

    new_message = Message(chat_id=chat_id, sender_id=sender_id, content=content)
    db.session.add(new_message)
    db.session.commit()

    message_schema = MessageSchema()
    return jsonify(message_schema.dump(new_message)), 201

@app.route('/chats/<int:chat_id>', methods=['DELETE'])
@jwt_required()
def delete_chat(chat_id):
    chat = Chat.query.get(chat_id)
    if not chat:
        return jsonify({"error": "Chat not found"}), 404

    Message.query.filter_by(chat_id=chat_id).delete()
    db.session.delete(chat)
    db.session.commit()

    return jsonify({"message": f"Chat with ID {chat_id} and all its messages deleted successfully."}), 200

@app.route('/logout-page')
def logout_page():
    session.pop('token', None)
    return redirect(url_for('login_page'))

@app.route('/chats-page', methods=['GET', 'POST'])
def chats_page():
    token = session.get('token')
    if not token:
        return redirect(url_for('login_page'))

    try:
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']
    except Exception:
        flash("Срок действия токена истёк. Пожалуйста, войдите снова.")
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        chat_name = request.form.get('name')
        if chat_name:
            new_chat = Chat(name=chat_name)
            db.session.add(new_chat)
            db.session.commit()

            # Добавляем первое сообщение от пользователя
            initial_message = Message(
                chat_id=new_chat.id,
                sender_id=user_id,
                content="Чат создан"
            )
            db.session.add(initial_message)
            db.session.commit()

            flash("Чат создан")
        else:
            flash("Имя чата не задано")

        return redirect(url_for('chats_page'))

    # Получаем только чаты, где пользователь уже отправил сообщения
    chats = (
        db.session.query(Chat)
        .join(Message, Chat.id == Message.chat_id)
        .filter(Message.sender_id == user_id)
        .distinct()
        .all()
    )

    chat_schema = ChatSchema(many=True)
    return render_template('chats.html', chats=chat_schema.dump(chats))



@app.route('/chats/<int:chat_id>/messages-page', methods=['GET', 'POST'])
def view_chat(chat_id):
    token = session.get('token')
    if not token:
        return redirect(url_for('login_page'))

    try:
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']
    except Exception:
        flash("Срок действия токена истёк. Пожалуйста, войдите снова.")
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            new_message = Message(chat_id=chat_id, sender_id=user_id, content=content)
            db.session.add(new_message)
            db.session.commit()
        return redirect(url_for('view_chat', chat_id=chat_id))

    # Загрузка сообщений с отправителями
    messages = (
        db.session.query(Message, User)
        .join(User, Message.sender_id == User.id)
        .filter(Message.chat_id == chat_id)
        .order_by(Message.timestamp.asc())
        .all()
    )

    # Формируем список словарей для шаблона
    formatted_messages = [
        {
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'sender': user.username,
            'content': message.content
        }
        for message, user in messages
    ]

    return render_template('messages.html', messages=formatted_messages, chat_id=chat_id)

if __name__ == '__main__':
    app.run(debug=True)
