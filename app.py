import os
from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-secret-key')

# Initialize extensions
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app, model_class=Base)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # type: ignore

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Models
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, title: str, desc: str, **kwargs):
        super().__init__(**kwargs)
        self.title = title
        self.desc = desc

    def __repr__(self) -> str:
        return f"{self.id} - {self.title}"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

    def __init__(self, username: str, password: str, **kwargs):
        super().__init__(**kwargs)
        self.username = username
        self.password = password

    def __repr__(self):
        return f'<User: {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# Routes
@app.route("/register", methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    # Use form data directly from request.form dictionary
    if 'username' not in request.form or 'password' not in request.form:
        flash("Username and password are required.", "danger")
        return redirect("/register")
    
    username = request.form['username']
    password = request.form['password']

    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect("/register")

    if len(password) < 6:
        flash("Password must be at least 6 characters long.", "danger")
        return redirect("/register")

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash("Username already exists!", "danger")
        return redirect("/register")

    try:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect("/login")
    except Exception as e:
        db.session.rollback()
        flash("Registration failed. Please try again.", "danger")
        return redirect("/register")

@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect("/")
    
    if request.method == 'POST':
        # Check if form fields exist
        if 'username' not in request.form or 'password' not in request.form:
            flash("Username and password are required.", "danger")
            return redirect("/login")
        
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect("/login")

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect("/")
        else:
            flash("Invalid username or password.", "danger")
    
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect("/login")

@app.route('/', methods=['GET', 'POST'])
@login_required
def publish():
    if request.method == 'POST':
        # Check if form fields exist
        if 'title' not in request.form or 'desc' not in request.form:
            flash("Title and description are required.", "danger")
            return redirect("/")
        
        title = request.form['title']
        desc = request.form['desc']

        if not title or not desc:
            flash("Title and description are required.", "danger")
            return redirect("/")

        todo = Todo(title=title, desc=desc)
        
        try:
            db.session.add(todo)
            db.session.commit()
            flash("Todo added successfully!", "success")
            return redirect("/")
        except Exception as e:
            db.session.rollback()
            flash("Error adding todo.", "danger")
    
    all_todos = Todo.query.all()
    return render_template('index.html', alltodo=all_todos)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    todo = Todo.query.get_or_404(id)
    
    try:
        db.session.delete(todo)
        db.session.commit()
        flash("Todo deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error deleting todo.", "danger")
    
    return redirect("/")

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    todo = Todo.query.get_or_404(id)
    
    if request.method == 'POST':
        # Check if form fields exist
        if 'title' not in request.form or 'desc' not in request.form:
            flash("Title and description are required.", "danger")
            return redirect(f"/update/{id}")
        
        title = request.form['title']
        desc = request.form['desc']

        if not title or not desc:
            flash("Title and description are required.", "danger")
            return redirect(f"/update/{id}")

        todo.title = title
        todo.desc = desc
        
        try:
            db.session.commit()
            flash("Todo updated successfully!", "success")
            return redirect('/')
        except Exception as e:
            db.session.rollback()
            flash("Error updating todo.", "danger")
    
    return render_template('update.html', todo=todo)

if __name__ == '__main__':
    app.run(debug=True)