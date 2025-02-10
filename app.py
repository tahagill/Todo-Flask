from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, current_user, logout_user, login_required
from flask_migrate import Migrate

# Define your base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Create the Flask app
app = Flask(__name__)

# Configure the SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.secret_key = 'TEST_KEY'

login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)

# Initialize SQLAlchemy with model_class set to Base
db = SQLAlchemy(app, model_class=Base)
migrate = Migrate(app, db)

class Todo(db.Model):
    sn = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"{self.sn} - {self.title}"

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    uid = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    role = db.Column(db.String)
    description = db.Column(db.String())

    def __repr__(self):
        return f'<User: {self.username}, Role: {self.role}>'
    
    def get_id(self):
        return self.uid

@login_manager.user_loader
def load_user(uid):
    return User.query.get(uid)

@app.route("/register", methods=['GET', 'POST']) # type: ignore
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password) # type: ignore

        db.session.add(user)
        db.session.commit()
        flash("Registration successful!", "success")
        return redirect("/login")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect('/')
        else:
            flash("Login failed. Check your credentials.", "danger")

    return render_template('login.html')

@app.route("/logout")
@login_required
def log_out():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect("/login")

@app.route('/', methods=['GET', 'POST'])
@login_required
def publish():
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']

        todo = Todo(title=title, desc=desc) # type: ignore
        db.session.add(todo)
        db.session.commit()
        flash("Todo added successfully!", "success")

    alltodo = Todo.query.all()
    return render_template('index.html', alltodo=alltodo)

@app.route('/delete/<int:sn>', methods=['GET', 'POST'])
def delete(sn):
    todo = Todo.query.filter_by(sn=sn).first()
    if todo:
        db.session.delete(todo)
        db.session.commit()
        flash("Todo deleted successfully!", "success")
    else:
        flash("Todo not found.", "danger")
    return redirect("/")

@app.route('/update/<int:sn>', methods=['GET', 'POST'])
def update(sn):
    todo = Todo.query.filter_by(sn=sn).first()
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        todo.title = title # type: ignore
        todo.desc = desc # type: ignore
        db.session.commit()
        flash("Todo updated successfully!", "success")
        return redirect('/')
    
    return render_template('update.html', todo=todo)

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
