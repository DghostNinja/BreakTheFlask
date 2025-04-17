from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os
import ldap3

app = Flask(__name__)

DB_FILE = "vulnerable.db"
LDAP_SERVER = "ldap://localhost:389"
LDAP_BASE_DN = "dc=example,dc=com"

def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            INSERT INTO users (username, password)
            VALUES
            ("admin", "password123"),
            ("john", "doe123"),
            ("jane", "secret")
        ''')
        conn.commit()
        conn.close()
        print("[+] Database initialized.")

@app.route('/')
def index():
    return """
    <h1> Injection Vulnerable Web App</h1>
    <p>This app contains multiple injection flaws for research purposes only.</p>
    <ul>
        <li><a href='/login'>SQL Injection (Login Form)</a></li>
        <li><a href='/xss?name=World'>Cross-Site Scripting (XSS)</a></li>
        <li><a href='/terminal'>Command Injection (Terminal)</a></li>
        <li><a href='/ldap-login'>LDAP Injection (Fake Auth)</a></li>
    </ul>
    """

@app.route('/login', methods=['GET', 'POST'])
def sqli():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"[DEBUG] SQL Query: {query}")
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()

        if result:
            return f"<h3>Welcome, {username}!</h3><p>Login successful.</p>"
        else:
            return "<p>Login failed. Invalid credentials.</p>"

    return '''
    <h2>SQL Injection Login</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" /><br>
        <input type="password" name="password" placeholder="Password" /><br>
        <input type="submit" value="Login" />
    </form>
    '''

@app.route('/xss')
def xss():
    name = request.args.get('name', '')
    html = f"""
    <h2>Reflected XSS Demo</h2>
    <form method='GET'>
        <input type='text' name='name' placeholder='Enter your name'>
        <input type='submit' value='Greet'>
    </form>
    <p>Hello, {name}</p>
    """
    return render_template_string(html)

@app.route('/terminal', methods=['GET', 'POST'])
def cmd():
    output = ''
    if request.method == 'POST':
        command = request.form.get('cmd', '')
        print(f"[DEBUG] Executing command: {command}")
        output = os.popen(command).read()

    return f"""
    <h2>Command Execution</h2>
    <form method="POST">
        <input type="text" name="cmd" placeholder="Enter system command">
        <input type="submit" value="Run">
    </form>
    <pre>{output}</pre>
    """

@app.route('/ldap-login', methods=['GET', 'POST'])
def ldap_login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        server = ldap3.Server(LDAP_SERVER, get_info=ldap3.NONE)
        conn = ldap3.Connection(server)
        conn.bind()

        search_filter = f"(&(uid={username})(userPassword={password}))"
        print(f"[DEBUG] LDAP Search Filter: {search_filter}")

        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            attributes=ldap3.ALL_ATTRIBUTES
        )

        if conn.entries:
            return f"<h3>Welcome, {username}!</h3><p>LDAP login successful.</p>"
        else:
            return "<p>LDAP login failed.</p>"

    return '''
    <h2>LDAP Login</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="LDAP Username" /><br>
        <input type="password" name="password" placeholder="LDAP Password" /><br>
        <input type="submit" value="Login" />
    </form>
    '''

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
