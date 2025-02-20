import os
import time
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

# Configuration de l'application
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB

# Initialisation de la base de données
db = SQLAlchemy(app)

# --- Modèles ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(100), nullable=False)
    profile_pic = db.Column(db.String(100), default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    image_filename = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    is_read = db.Column(db.Boolean, default=False)

# --- Décorateurs ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Veuillez vous connecter pour accéder à cette page.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes principales ---
@app.route('/')
@login_required
def index():
    user = User.query.get(session['user_id'])
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', user=user, posts=posts)

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    current_user_id = session['user_id']
    
    if request.method == 'POST':
        receiver_id = request.form.get('receiver_id')
        content = request.form.get('message')
        
        if not receiver_id or not content:
            flash("Destinataire ou message manquant", "error")
            return redirect(url_for('messages'))
        
        new_message = Message(
            sender_id=current_user_id,
            receiver_id=receiver_id,
            content=content
        )
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('messages', user_id=receiver_id))
    
    # Récupération des conversations
    conversations = db.session.query(
        Message.sender_id,
        Message.receiver_id
    ).filter(
        (Message.sender_id == current_user_id) | 
        (Message.receiver_id == current_user_id)
    ).distinct().all()
    
    # Traitement des conversations
    processed_conversations = []
    for conv in conversations:
        other_user_id = conv[0] if conv[0] != current_user_id else conv[1]
        other_user = User.query.get(other_user_id)
        last_message = Message.query.filter(
            ((Message.sender_id == current_user_id) & (Message.receiver_id == other_user_id)) |
            ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user_id))
        ).order_by(Message.timestamp.desc()).first()
        
        processed_conversations.append({
            'user': other_user,
            'last_message': last_message,
            'unread': Message.query.filter_by(receiver_id=current_user_id, sender_id=other_user_id, is_read=False).count()
        })
    
    # Messages avec un utilisateur spécifique
    selected_user_id = request.args.get('user_id')
    selected_user = None
    messages = []
    
    if selected_user_id:
        selected_user = User.query.get(selected_user_id)
        messages = Message.query.filter(
            ((Message.sender_id == current_user_id) & (Message.receiver_id == selected_user_id)) |
            ((Message.sender_id == selected_user_id) & (Message.receiver_id == current_user_id))
        ).order_by(Message.timestamp.asc()).all()
        
        # Marquer les messages comme lus
        Message.query.filter_by(receiver_id=current_user_id, sender_id=selected_user_id, is_read=False).update({'is_read': True})
        db.session.commit()
    
    return render_template('messages.html',
                         conversations=processed_conversations,
                         messages=messages,
                         selected_user=selected_user,
                         current_user_id=current_user_id)

# ... (Gardez le reste de vos routes existantes pour login/register/settings etc.) ...

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)