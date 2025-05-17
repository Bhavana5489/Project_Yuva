from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField,TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError, Length
import bcrypt
from flask_mysqldb import MySQL
import MySQLdb.cursors

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
    role = SelectField("Role", choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
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


class CompleteTaskForm(FlaskForm):
    submit = SubmitField('Mark as Complete')

class NoteForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=255)])
    body = TextAreaField("Note", validators=[DataRequired()])
    submit = SubmitField("Save")


class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    body = TextAreaField('Body', validators=[DataRequired()])
    submit = SubmitField('Save Note')


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
        role = form.role.data
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
                       (name, email, hashed_password, role))
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
            session['user_role'] = user[4] if len(user) > 4 else 'user'

            # Route based on role
            if session['user_role'] == 'admin':
                return redirect(url_for('admin_dashboard'))  # Redirect to admin.html route
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password.")
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

# Dashboard
from flask import Flask, render_template, redirect, url_for, session, flash, request
import MySQLdb.cursors

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Fetch tasks
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT id, title, description, priority
        FROM tasks
        WHERE user_id = %s AND (completed IS NULL OR completed = FALSE)
    """, (user_id,))
    tasks = cursor.fetchall()
    cursor.close()

    # Fetch notes
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT id, title, body, created_at
        FROM notes
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (user_id,))
    notes = cursor.fetchall()
    cursor.close()

    user = (session.get('user_name'), session.get('user_email'))
    delete_form = DeleteTaskForm()
    complete_form = CompleteTaskForm()

    return render_template(
        'dashboard.html',
        user=user,
        tasks=tasks,
        delete_form=delete_form,
        complete_form=complete_form,
        notes=notes  # Pass notes to template
    )


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
    is_admin = session.get('user_email') == 'admin@example.com'

    cursor = mysql.connection.cursor()
    if is_admin:
        cursor.execute("SELECT * FROM tasks WHERE id = %s", (task_id,))
    else:
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
    return redirect(request.referrer or url_for('dashboard'))





# Admin Dashboard
@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))


    add_form = TaskForm()
    delete_form = DeleteTaskForm()

    cursor = mysql.connection.cursor()

    if add_form.validate_on_submit():
        title = add_form.title.data
        description = add_form.description.data
        priority = add_form.priority.data

        # For simplicity, we assign all admin-created tasks to admin (or use a dummy user_id like 0)
        cursor.execute("INSERT INTO tasks (user_id, title, description, priority) VALUES (%s, %s, %s, %s)",
                       (session['user_id'], title, description, priority))
        mysql.connection.commit()
        flash("Task added successfully.")
        return redirect(url_for('admin_dashboard'))

    cursor.execute("SELECT id, title, description, priority FROM tasks")
    tasks = cursor.fetchall()
    cursor.close()

    user = (session.get('user_name'), session.get('user_email'))

    return render_template('admin.html', user=user, tasks=tasks, add_form=add_form, delete_form=delete_form)




@app.route('/task/complete/<int:task_id>', methods=['POST'])
def complete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cursor = mysql.connection.cursor()

    # Optional: Check if the task belongs to the user
    cursor.execute("SELECT * FROM tasks WHERE id = %s AND user_id = %s", (task_id, user_id))
    task = cursor.fetchone()
    if not task:
        cursor.close()
        flash("Task not found or unauthorized.")
        return redirect(url_for('dashboard'))

    # Set a `completed` field to TRUE (you need this column in DB)
    cursor.execute("UPDATE tasks SET completed = TRUE WHERE id = %s", (task_id,))
    mysql.connection.commit()
    cursor.close()

    flash("Task marked as completed.")
    return redirect(url_for('dashboard'))





@app.route('/pages', methods=['GET', 'POST'])
def pages():
    # Check if the user is logged in
    user_id = session.get('user_id')
    if not user_id:
        flash("Session expired or unauthorized access. Please log in again.", "danger")
        return redirect(url_for('login'))

    # DEBUG: Print full session contents
    print("ENTERED /pages with session:", dict(session))

    form = NoteForm()

    if form.validate_on_submit():
        title = form.title.data
        body = form.body.data

        # Insert note into database
        cursor = mysql.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO notes (user_id, title, body) VALUES (%s, %s, %s)",
                (user_id, title, body)
            )
            mysql.connection.commit()
            flash('Note saved successfully!', 'success')
        except Exception as e:
            flash(f"Error saving note: {e}", 'danger')
        finally:
            cursor.close()

        return redirect(url_for('pages'))

    # Fetch user notes
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM notes WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    notes = cursor.fetchall()
    cursor.close()

    return render_template('pages.html', form=form, notes=notes)



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
        return redirect(url_for('dashboard'))

    return render_template('viewnote.html', note=note)







# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
