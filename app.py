import os
import time
from flask import Flask, render_template, request, redirect, session, url_for, flash # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from werkzeug.utils import secure_filename # type: ignore
from functools import wraps

# Configuration de l'application
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Limite de 2MB

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
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Votre logique de connexion ici
    return render_template('login.html')


@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    try:
        current_user_id = session['user_id']
        current_user = User.query.get(current_user_id)

        # Gestion de l'envoi de message
        if request.method == 'POST':
            receiver_id = request.form.get('receiver_id')
            content = request.form.get('message', '').strip()

            if not receiver_id or not content:
                flash("Destinataire ou message manquant", "error")
                return redirect(url_for('messages'))

            if not User.query.get(receiver_id):
                flash("Destinataire invalide", "error")
                return redirect(url_for('messages'))

            new_message = Message(
                sender_id=current_user_id,
                receiver_id=receiver_id,
                content=content
            )
            db.session.add(new_message)
            db.session.commit()

        # Récupération des conversations
        sent_conversations = db.session.query(Message.receiver_id).filter_by(sender_id=current_user_id).distinct()
        received_conversations = db.session.query(Message.sender_id).filter_by(receiver_id=current_user_id).distinct()
        
        participant_ids = {id for (id,) in sent_conversations} | {id for (id,) in received_conversations}
        conversations = []
        
        for user_id in participant_ids:
            user = User.query.get(user_id)
            last_message = Message.query.filter(
                ((Message.sender_id == current_user_id) & (Message.receiver_id == user_id)) |
                ((Message.sender_id == user_id) & (Message.receiver_id == current_user_id))
            ).order_by(Message.timestamp.desc()).first()
            
            conversations.append({
                'user': user,
                'last_message': last_message,
                'unread_count': Message.query.filter_by(sender_id=user_id, receiver_id=current_user_id, is_read=False).count()
            })

        # Gestion de la conversation sélectionnée
        selected_user_id = request.args.get('user_id')
        selected_user = None
        messages = []
        
        if selected_user_id:
            selected_user = User.query.get(selected_user_id)
            if selected_user:
                messages = Message.query.filter(
                    ((Message.sender_id == current_user_id) & (Message.receiver_id == selected_user_id)) |
                    ((Message.sender_id == selected_user_id) & (Message.receiver_id == current_user_id))
                ).order_by(Message.timestamp.asc()).all()
                
                # Marquer les messages comme lus
                Message.query.filter_by(sender_id=selected_user_id, receiver_id=current_user_id, is_read=False).update({'is_read': True})
                db.session.commit()

        return render_template('messages.html',
                            current_user=current_user,
                            conversations=conversations,
                            selected_user=selected_user,
                            messages=messages)

    except Exception as e:
        print(f"ERREUR CRITIQUE: {str(e)}")
        db.session.rollback()
        flash("Une erreur s'est produite. Veuillez réessayer.", "error")
        return redirect(url_for('index'))

# --- Routes d'authentification ---
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

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash("Déconnexion réussie.", "success")
    return redirect(url_for('login'))

# --- Routes supplémentaires ---
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

@app.route('/post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content')
    # Pour l'instant, on ne gère pas l'upload d'image pour les posts ici
    if content:
        new_post = Post(content=content, user_id=session['user_id'])
        db.session.add(new_post)
        db.session.commit()
    return redirect(url_for('index'))

# --- Fonctions utilitaires ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# --- Point d'entrée ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)