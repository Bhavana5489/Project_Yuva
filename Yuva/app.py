from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL

app = Flask(__name__)


# MySQL Configuration (do not change)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)
csrf = CSRFProtect(app)  # Enable CSRF protection globally

# Registration Form
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

# Login Form
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# Task Form
class TaskForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = StringField("Description")
    priority = SelectField("Priority", choices=[('High', 'High'), ('Mid', 'Mid'), ('Low', 'Low')], validators=[DataRequired()])
    submit = SubmitField("Add Task")

class DeleteTaskForm(FlaskForm):
    submit = SubmitField('Remove')


# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['user_email'] = user[2]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password.")
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, title, description, priority FROM tasks WHERE user_id = %s", (user_id,))
    tasks = cursor.fetchall()
    cursor.close()

    user = (session.get('user_name'), session.get('user_email'))
    delete_form = DeleteTaskForm()
    return render_template('dashboard.html', user=user, tasks=tasks, delete_form=delete_form)


# Add Task
@app.route('/add-task', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = TaskForm()
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        priority = form.priority.data
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO tasks (user_id, title, description, priority) VALUES (%s, %s, %s, %s)",
                       (user_id, title, description, priority))
        mysql.connection.commit()
        cursor.close()

        flash("Task added successfully.")
        return redirect(url_for('dashboard'))
    return render_template('addtask.html', form=form)

# Update Task
@app.route('/task/update/<int:task_id>', methods=['POST'])
def update_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    title = request.form.get('title')
    description = request.form.get('description')
    priority = request.form.get('priority')
    user_id = session['user_id']

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM tasks WHERE id = %s AND user_id = %s", (task_id, user_id))
    task = cursor.fetchone()
    if not task:
        cursor.close()
        flash("Task not found or unauthorized.")
        return redirect(url_for('dashboard'))

    cursor.execute("UPDATE tasks SET title = %s, description = %s, priority = %s WHERE id = %s",
                   (title, description, priority, task_id))
    mysql.connection.commit()
    cursor.close()

    flash("Task updated successfully.")
    return redirect(url_for('dashboard'))

# Delete Task
@app.route('/task/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM tasks WHERE id = %s AND user_id = %s", (task_id, user_id))
    task = cursor.fetchone()
    if not task:
        cursor.close()
        flash("Task not found or unauthorized.")
        return redirect(url_for('dashboard'))

    cursor.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
    mysql.connection.commit()
    cursor.close()

    flash("Task deleted successfully.")
    return redirect(url_for('dashboard'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
