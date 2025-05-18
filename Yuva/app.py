from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError, Length
import bcrypt
from flask_mysqldb import MySQL
import MySQLdb.cursors
from collections import Counter


# ----------------- App Configuration -----------------
app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)
csrf = CSRFProtect(app)

# ----------------- Forms -----------------
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = SelectField("Role", choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (field.data,))
        if cursor.fetchone():
            cursor.close()
            raise ValidationError('Email Already Taken')
        cursor.close()

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class TaskForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = StringField("Description")
    priority = SelectField("Priority", choices=[('High', 'High'), ('Mid', 'Mid'), ('Low', 'Low')], validators=[DataRequired()])
    submit = SubmitField("Add Task")

class DeleteTaskForm(FlaskForm):
    submit = SubmitField('Remove')

class CompleteTaskForm(FlaskForm):
    submit = SubmitField('Mark as Complete')

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=255)])
    body = TextAreaField('Body', validators=[DataRequired()])
    submit = SubmitField('Save Note')

class CompleteForm(FlaskForm):
    submit = SubmitField('Mark Complete')

# ----------------- Routes -----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
                       (form.name.data, form.email.data, hashed_password, form.role.data))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users WHERE email = %s", (form.email.data,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user['password'].encode('utf-8')):
            session.update({
                'user_id': user['id'],
                'user_name': user['name'],
                'user_email': user['email'],
                'user_role': user.get('role', 'user')
            })
            return redirect(url_for('admin_dashboard' if session['user_role'] == 'admin' else 'dashboard'))
        flash("Login failed. Please check your email and password.")
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE email = %s", (session['user_email'],))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        return "User not found", 404

    cursor.execute("SELECT * FROM tasks WHERE user_id = %s", (user['id'],))
    tasks = cursor.fetchall()

    cursor.execute("SELECT * FROM notes WHERE user_id = %s", (user['id'],))
    notes = cursor.fetchall()

    # Count task priorities
    priority_data = {'High': 0, 'Mid': 0, 'Low': 0}
    for task in tasks:
        if task['priority'] in priority_data:
            priority_data[task['priority']] += 1

    cursor.close()

    return render_template(
    'dashboard.html',
    user=user,
    tasks=tasks,
    notes=notes,
    priority_data=priority_data,
    complete_forms={task['id']: CompleteForm(prefix=str(task['id'])) for task in tasks}  # <- This must be defined
)


@app.route('/task/complete/<int:task_id>', methods=['POST'])
def complete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM tasks WHERE id = %s AND user_id = %s", (task_id, session['user_id']))
    task = cursor.fetchone()

    if not task:
        cursor.close()
        flash("Task not found or unauthorized.")
        return redirect(url_for('dashboard'))

    cursor.execute("UPDATE tasks SET completed = TRUE WHERE id = %s", (task_id,))
    mysql.connection.commit()
    cursor.close()

    flash("Task marked as completed.")
    return redirect(url_for('dashboard'))

@app.route('/add-task', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = TaskForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO tasks (user_id, title, description, priority) VALUES (%s, %s, %s, %s)",
                       (session['user_id'], form.title.data, form.description.data, form.priority.data))
        mysql.connection.commit()
        cursor.close()

        flash("Task added successfully.")
        return redirect(url_for('admin_dashboard' if session.get('user_role') == 'admin' else 'dashboard'))

    return render_template('addtask.html', form=form)

@app.route('/task/update/<int:task_id>', methods=['POST'])
def update_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM tasks WHERE id = %s AND user_id = %s", (task_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        flash("Task not found or unauthorized.")
        return redirect(url_for('dashboard'))

    cursor.execute("UPDATE tasks SET title = %s, description = %s, priority = %s WHERE id = %s",
                   (request.form['title'], request.form['description'], request.form['priority'], task_id))
    mysql.connection.commit()
    cursor.close()

    flash("Task updated successfully.")
    return redirect(url_for('dashboard'))

@app.route('/task/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    if session.get('user_role') == 'admin':
        cursor.execute("SELECT * FROM tasks WHERE id = %s", (task_id,))
    else:
        cursor.execute("SELECT * FROM tasks WHERE id = %s AND user_id = %s", (task_id, session['user_id']))
    if not cursor.fetchone():
        cursor.close()
        flash("Task not found or unauthorized.")
        return redirect(url_for('dashboard'))

    cursor.execute("DELETE FROM tasks WHERE id = %s", (task_id,))
    mysql.connection.commit()
    cursor.close()

    flash("Task deleted successfully.")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/pages', methods=['GET', 'POST'])
def pages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = NoteForm()
    if form.validate_on_submit():
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s)",
                       (session['user_id'], form.title.data, form.body.data))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('admin_dashboard' if session.get('user_role') == 'admin' else 'dashboard'))

    return render_template('pages.html', form=form)

@app.route('/note/<int:note_id>')
def view_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
    note = cursor.fetchone()
    cursor.close()

    if not note:
        flash("Note not found or unauthorized.")
        return redirect(url_for('admin_dashboard' if session.get('user_role') == 'admin' else 'dashboard'))

    return render_template('viewnote.html', note=note)

@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    add_form = TaskForm()
    delete_form = DeleteTaskForm()

    cursor = mysql.connection.cursor()

    if add_form.validate_on_submit():
        cursor.execute(
            "INSERT INTO tasks (user_id, title, description, priority) VALUES (%s, %s, %s, %s)",
            (session['user_id'], add_form.title.data, add_form.description.data, add_form.priority.data)
        )
        mysql.connection.commit()
        flash("Task added successfully.")
        return redirect(url_for('admin_dashboard'))

    # Get all tasks
    cursor.execute("SELECT id, title, description, priority FROM tasks")
    tasks = cursor.fetchall()

    # Count tasks by priority
    cursor.execute("""
    SELECT priority, COUNT(*) AS count
    FROM tasks
    GROUP BY priority
""")
    priority_counts = cursor.fetchall()

# Using tuple indexing
    high = mid = low = 0
    for row in priority_counts:
        if row[0] == 'High':
            high = row[1]
        elif row[0] == 'Mid':
            mid = row[1]
        elif row[0] == 'Low':
            low = row[1]

    cursor.close()

    user = (session.get('user_name'), session.get('user_email'))

    # Pass counts as tuple
    return render_template(
        'admin.html',
        user=user,
        tasks=tasks,
        add_form=add_form,
        delete_form=delete_form,
        priority_counts=(high, mid, low)
    )

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)