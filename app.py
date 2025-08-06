from flask import Flask, render_template, url_for, request, redirect, session
from flaskext.mysql import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure random secret key

# MySQL Configuration
mysql = MySQL()
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'todo'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

def get_db_connection():
    conn = mysql.connect()
    cursor = conn.cursor()
    return conn, cursor

def validate_input(input_str, max_length=50):
    """Basic input validation to prevent XSS and SQL injection"""
    if not input_str or len(input_str) > max_length:
        return False
    # Basic check for suspicious characters
    forbidden_chars = ['<', '>', ';', "'", '"', '\\']
    return not any(char in input_str for char in forbidden_chars)

@app.route('/', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        un = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()
        cpw = request.form.get('confpassword', '').strip()

        # Input validation
        if not all([validate_input(un), validate_input(pw), validate_input(cpw)]):
            return '''
            <script>
                alert("Invalid input detected!");
                window.history.back();
            </script>
            '''

        conn, cursor = get_db_connection()
        try:
            # Check if username exists
            cursor.execute("SELECT username FROM users WHERE username = %s", (un,))
            if cursor.fetchone():
                return '''
                <script>
                    alert("Username already exists!");
                    window.history.back();
                </script>
                '''

            # Password validation
            if pw != cpw:
                return '''
                <script>
                    alert("Passwords do not match!");
                    window.history.back();
                </script>
                '''
            if len(pw) < 8:
                return '''
                <script>
                    alert("Password must be at least 8 characters long!");
                    window.history.back();
                </script>
                '''

            # Hash password before storing
            hashed_pw = generate_password_hash(pw)
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (un, hashed_pw))
            conn.commit()
            return '''
            <script>
                alert("Signup successful!");
                window.location.href='/login';
            </script>
            '''
        except Exception as e:
            conn.rollback()
            return f'''
            <script>
                alert("Error: {str(e)}");
                window.history.back();
            </script>
            '''
        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usnm = request.form.get('loginusername', '').strip()
        pswd = request.form.get('loginpassword', '').strip()

        if not all([validate_input(usnm), validate_input(pswd)]):
            return '''
            <script>
                alert("Invalid input detected!");
                window.history.back();
            </script>
            '''

        conn, cursor = get_db_connection()
        try:
            cursor.execute("SELECT username, password FROM users WHERE username = %s", (usnm,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user[1], pswd):
                session['username'] = user[0]
                session.permanent = False  # Session expires when browser closes
                return '''
                <script>
                    alert("Login Successful!");
                    window.location.href='/home';
                </script>
                '''
            else:
                return '''
                <script>
                    alert("Invalid Username or Password!");
                    window.history.back();
                </script>
                '''
        except Exception as e:
            return f'''
            <script>
                alert("Error: {str(e)}");
                window.history.back();
            </script>
            '''
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')

@app.route('/home')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn, cursor = get_db_connection()
    try:
        cursor.execute("SELECT srno, task FROM tasks WHERE username = %s", (session['username'],))
        rows = cursor.fetchall()
        return render_template('index.html', tasks=rows)
    finally:
        cursor.close()
        conn.close()

@app.route('/submit', methods=['POST'])
def submit():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    task = request.form.get('task', '').strip()
    if not validate_input(task, max_length=255):
        return '''
        <script>
            alert("Invalid task content!");
            window.history.back();
        </script>
        '''
    
    conn, cursor = get_db_connection()
    try:
        cursor.execute("INSERT INTO tasks (task, username) VALUES (%s, %s)", (task, session['username']))
        conn.commit()
        return redirect(url_for('index'))
    except Exception as e:
        conn.rollback()
        return f'''
        <script>
            alert("Error: {str(e)}");
            window.history.back();
        </script>
        '''
    finally:
        cursor.close()
        conn.close()

@app.route('/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'username' not in session:
        return '', 403
    
    conn, cursor = get_db_connection()
    try:
        # Verify task belongs to user before deleting
        cursor.execute("SELECT username FROM tasks WHERE srno = %s", (task_id,))
        task_owner = cursor.fetchone()
        
        if task_owner and task_owner[0] == session['username']:
            cursor.execute("DELETE FROM tasks WHERE srno = %s", (task_id,))
            conn.commit()
            return '', 204
        else:
            return '', 403
    except Exception as e:
        conn.rollback()
        return '', 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=False)  # Debug should be False in production