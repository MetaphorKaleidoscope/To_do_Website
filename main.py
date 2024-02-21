# To do Website
# A tasks management website

from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreateTaskForm, RegisterForm, LoginForm, NoteForm
from flask_gravatar import Gravatar
import os  # To take data for db table file
from dotenv import load_dotenv
from functools import wraps
from flask import abort
from datetime import datetime

STATUS = ['To do', 'Doing', 'Done']
now = datetime.today()
date = now.strftime('%Y-%m-%d')

basedir = os.path.abspath(os.path.dirname(__file__))  # To take data for db table file
app = Flask(__name__)
load_dotenv('.env')
SECRET_KEY = os.getenv('SECRET_KEY')
app.config['SECRET_KEY'] = SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap(app)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return RegisterUser.query.get(int(user_id))


# Only administration
def admin_only(f):
    @wraps(f)
    def decorate_function(*args, **kwargs):
        if not current_user:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorate_function


# #CONFIGURE TABLES
class RegisterUser(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    tasks = relationship('Task', back_populates='users')
    notes = relationship('NoteUser', back_populates='users')


class Task(db.Model):
    __tablename__ = "task_website"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), db.ForeignKey('users.name'))
    users = relationship('RegisterUser', back_populates='tasks')
    name = db.Column(db.String(250), unique=True, nullable=False)
    activities = db.Column(db.String(500), nullable=True)
    priority = db.Column(db.String(500), nullable=False)
    state = db.Column(db.String(500), nullable=False)
    due_date = db.Column(db.DateTime('%Y-%m-%d'), nullable=False)
    notes = relationship('NoteUser', back_populates='task_website')


class NoteUser(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer,  db.ForeignKey('task_website.id'))
    note = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), db.ForeignKey('users.name'))
    users = relationship('RegisterUser', back_populates='notes')
    task_website = relationship('Task', back_populates='notes')


with app.app_context():  # Add after add a table  or tablename
    db.create_all()
    db.session.commit()


@app.route('/')
def get_all_tasks():
    tasks = Task.query.all()
    return render_template("index.html", all_tasks=tasks, status=STATUS, date=now)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        email = form.email.data
        user = RegisterUser.query.filter_by(email=email).first()
        if not user:
            with app.app_context():
                db.create_all()
                new_user = RegisterUser(email=email, password=password_hash, name=form.name.data)
                db.session.add(new_user)
                db.session.commit()
                # Log and authenticate user after adding details to database
                login_user(new_user)
                return redirect(url_for("get_all_tasks"))
        else:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = RegisterUser.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_tasks"))
            else:
                flash("Wrong password -Try Again!")
        else:
            flash("That email doesn't Exist! -Try Again!")
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_tasks'))


@app.route("/task/<int:task_id>", methods=['GET', 'POST'])
def show_task(task_id):
    form_note = NoteForm()
    requested_task = Task.query.get(task_id)
    requested_notes = requested_task.notes
    if form_note.validate_on_submit():
        if 'UserMixin' not in str(current_user):
            with app.app_context():
                db.create_all()
                new_note = NoteUser(task_id=task_id, note=request.form.get('note'), users=current_user)
                db.session.add(new_note)
                db.session.commit()
                return redirect(url_for("get_all_tasks"))
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
    return render_template("task.html", task=requested_task, form=form_note, notes=requested_notes)


@app.route("/new-task", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_task():
    form = CreateTaskForm()
    if form.validate_on_submit():
        with app.app_context():
            db.create_all()
            new_task = Task(
                name=form.name.data,
                activities=form.activities.data,
                priority=form.priority.data,
                author=current_user.name,
                state=form.state.data,
                due_date=form.due_date.data,
            )
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for("get_all_tasks"))
    return render_template("make-task.html", form=form)


@app.route("/edit-task/<int:task_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_task(task_id):
    task = Task.query.get(task_id)
    edit_form = CreateTaskForm(
        name=task.name,
        activities=task.activities,
        priority=task.priority,
        author=task.author,
        state=task.state,
        due_date=task.due_date,
    )
    if edit_form.validate_on_submit():
        task.name = edit_form.name.data
        task.activities = edit_form.activities.data
        task.priority = edit_form.priority.data
        task.state = edit_form.state.data
        task.due_date = edit_form.due_date.data
        db.session.commit()
        return redirect(url_for("show_task", task_id=task_id))

    return render_template("make-task.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:task_id>")
@login_required
@admin_only
def delete_task(task_id):
    task_to_delete = Task.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_tasks'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
