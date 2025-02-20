import os
import time
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect('/login')
    
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')
    
    if not receiver_id or not content:
        return "Destinataire ou contenu manquant", 400
    
    new_message = Message(
        sender_id=session['user_id'],
        receiver_id=receiver_id,
        content=content
    )
    db.session.add(new_message)
    db.session.commit()
    
    return redirect('/messages')
@login_required
def messages():
    if request.method == 'POST':
        # Traitement de l'envoi d'un message
        message_text = request.form.get('message')
        # Vous ajouteriez ici la logique pour sauvegarder le message en base de données,
        # associer l'expéditeur et le destinataire, etc.
        flash("Message envoyé", "success")
        return redirect(url_for('messages'))
    
    # Pour un affichage dynamique, récupérez vos conversations/messages depuis la base
    conversations = []  # Remplacez par la requête vers votre modèle Conversation ou Message
    return render_template('messages.html', conversations=conversations)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuration pour l'upload d'images (photo de profil)
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Limite de 2MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)

# --- Modèles ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True)  # vous pouvez ajouter nullable=False si nécessaire
    password = db.Column(db.String(100), nullable=False)
    profile_pic = db.Column(db.String(100), default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    image_filename = db.Column(db.String(100))  # chemin relatif vers l'image uploadée
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    # Dans app.py
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    is_read = db.Column(db.Boolean, default=False)

    # Relations
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# --- Décorateur pour protéger les routes ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Veuillez vous connecter pour accéder à cette page.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

# Page d'accueil (Feed)
@app.route('/')
@login_required
def index():
    user = User.query.get(session['user_id'])
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', user=user, posts=posts)

# Inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        # Vérifie si l'utilisateur existe déjà par username ou email
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Nom d'utilisateur ou email déjà utilisé.", "error")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Inscription réussie. Vous pouvez maintenant vous connecter.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# Connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']
        password = request.form['password']
        # Recherche par nom d'utilisateur ou email
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Connexion réussie.", "success")
            return redirect(url_for('index'))
        flash("Identifiants incorrects.", "error")
        return render_template('login.html', error="Identifiants incorrects")
    return render_template('login.html')

# Déconnexion
@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash("Déconnexion réussie.", "success")
    return redirect(url_for('login'))

# Paramètres du profil
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        
        # Traitement de l'upload de la photo de profil
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{user.id}_{int(time.time())}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            # Stocke le chemin relatif (à partir du dossier static)
            user.profile_pic = os.path.join('uploads', unique_filename)
        
        # Met à jour le nom d'utilisateur et l'email
        if new_username and new_username != user.username:
            user.username = new_username
        if new_email and new_email != user.email:
            user.email = new_email
        
        db.session.commit()
        flash("Profil mis à jour avec succès.", "success")
        return redirect(url_for('index'))
    return render_template('settings.html', user=user)

# (Optionnel) Route de création de post
@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect('/login')
    
    user_id = session['user_id']
    
    # Récupérer les conversations
    conversations = db.session.query(
        Message.sender_id,
        Message.receiver_id
    ).filter(
        (Message.sender_id == user_id) | (Message.receiver_id == user_id)
    ).distinct().all()
    
    # Récupérer les messages avec un utilisateur spécifique
    other_user_id = request.args.get('user_id')
    messages = []
    if other_user_id:
        messages = Message.query.filter(
            ((Message.sender_id == user_id) & (Message.receiver_id == other_user_id)) |
            ((Message.sender_id == other_user_id) & (Message.receiver_id == user_id))
        ).order_by(Message.timestamp.asc()).all()
    
    return render_template('messages.html', conversations=conversations, messages=messages, user_id=user_id)
@login_required
def create_post():
    content = request.form.get('content')
    # Pour l'instant, on ne gère pas l'upload d'image pour les posts ici
    if content:
        new_post = Post(content=content, user_id=session['user_id'])
        db.session.add(new_post)
        db.session.commit()
    return redirect(url_for('index'))

# (Optionnel) Route pour la récupération de mot de passe (stub)
@app.route('/forgot_password')
def forgot_password():
    return "Fonctionnalité de récupération de mot de passe non implémentée."

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
