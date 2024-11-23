from flask import Flask, render_template, request, redirect, url_for, session, flash
import logging
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Chave secreta para uso de sessão

# Configuração de logging
logging.basicConfig(filename='login_attempts.log', level=logging.INFO)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password, admin=False):
        self.id = id
        self.username = username
        self.password = password
        self.admin = admin

users = [
    User(id=1, username="admin@example.com", password="adminpass", admin=True),
    User(id=2, username="user@example.com", password="password123", admin=False),
    User(id=3, username="1234567890", password="password123", admin=False)  # Exemplo de número de telefone
]

# Lista para armazenar tentativas de login
login_attempts = []

@login_manager.user_loader
def load_user(user_id):
    return next((user for user in users if user.id == int(user_id)), None)
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email_or_phone = request.form['email_or_phone']
    password = request.form['password']
    
    # Registrar tentativa de login
    logging.info(f'Tentativa de login - Usuário: {email_or_phone}, Senha: {password}')
    login_attempts.append({'username': email_or_phone, 'password': password})
    
    user = next((u for u in users if u.username == email_or_phone and u.password == password), None)
    if user:
        login_user(user)
        if user.admin:
            return redirect(url_for('admin'))
        return redirect(url_for('home'))
    flash('Nome de usuário ou senha incorretos.')
    return redirect(url_for('login'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email_or_phone = request.form['email_or_phone']
        password = request.form['password']
        admin = 'admin' in request.form and request.form['admin'] == 'on'
        if not any(u.username == email_or_phone for u in users):
            new_user = User(id=len(users) + 1, username=email_or_phone, password=password, admin=admin)
            users.append(new_user)
            flash('Registro bem-sucedido! Faça login para continuar.')
            return redirect(url_for('login'))
        flash('Usuário já existe. Escolha outro.')
    return render_template('register.html')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html', login_attempts=login_attempts)

if __name__ == '__main__':
    app.run(debug=True)
