import os
import sqlite3
import pickle
import json
import jwt
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, make_response, escape, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'hardcoded_secret_key'  # Hardcoded credentials
UPLOAD_FOLDER = 'uploads'
DEBUG_SECRET = 'SECRET_DEBUG_INFO=42'
JWT_SECRET = 'jwtsecret'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Real Vulnerabilities ---

# REAL VULNERABILITY: SQL Injection
@app.route('/search')
@log_benchmark("Real Vulnerability")
def search():
    q = request.args.get('q', '')
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)')
    c.execute("INSERT INTO users (name) VALUES ('admin'), ('user')")
    # SQL Injection
    try:
        query = f"SELECT * FROM users WHERE name = '{q}'"
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        results = [str(e)]
    return render_template('search.html', results=results, q=q, query=query)

# REAL VULNERABILITY: XSS
@app.route('/feedback', methods=['GET', 'POST'])
@log_benchmark("Real Vulnerability")
def feedback():
    msg = ''
    if request.method == 'POST':
        # XSS
        msg = request.form.get('msg', '')
    return render_template('feedback.html', msg=msg)

# REAL VULNERABILITY: Command Injection
@app.route('/run', methods=['GET', 'POST'])
@log_benchmark("Real Vulnerability")
def run():
    output = ''
    if request.method == 'POST':
        cmd = request.form.get('cmd', '')
        # Command Injection
        output = os.popen(f"echo Result: && {cmd}").read()
    return render_template('run.html', output=output)

# REAL VULNERABILITY: Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
@log_benchmark("Real Vulnerability")
def deserialize():
    # Insecure Deserialization
    data = request.get_data()
    try:
        obj = pickle.loads(data)
        return f"Deserialized: {obj}"
    except Exception as e:
        return str(e), 400

# REAL VULNERABILITY: Directory Traversal
@app.route('/files')
@log_benchmark("Real Vulnerability")
def files():
    # Directory Traversal
    path = request.args.get('path', '')
    try:
        with open(path, 'r') as f:
            content = f.read(200)
    except Exception as e:
        content = str(e)
    return render_template('files.html', path=path, content=content)

# REAL VULNERABILITY: Open Redirect
@app.route('/redirect')
@log_benchmark("Real Vulnerability")
def redirect_vuln():
    next_url = request.args.get('next', '/')
    # Open Redirect
    return redirect(next_url)

# REAL VULNERABILITY: Sensitive Data Exposure
@app.route('/debug')
@log_benchmark("Real Vulnerability")
def debug():
    # Sensitive Data Exposure
    return f"Debug info: {DEBUG_SECRET}"

# REAL VULNERABILITY: No Rate Limiting, Weak Password Policy
@app.route('/login', methods=['GET', 'POST'])
@log_benchmark("Real Vulnerability")
def login():
    # No Rate Limiting, Weak Password Policy
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == 'admin' and password == 'admin':
            msg = 'Login successful!'
        else:
            msg = 'Invalid credentials.'
    return render_template('login.html', msg=msg)

# REAL VULNERABILITY: Unrestricted File Upload
@app.route('/upload', methods=['GET', 'POST'])
@log_benchmark("Real Vulnerability")
def upload():
    # Unrestricted File Upload
    msg = ''
    if request.method == 'POST':
        file = request.files['file']
        file.save(os.path.join(UPLOAD_FOLDER, file.filename))
        msg = 'File uploaded!'
    return render_template('upload.html', msg=msg)

# REAL VULNERABILITY: CSRF (No token)
@app.route('/update-profile', methods=['POST'])
@log_benchmark("Real Vulnerability")
def update_profile():
    # CSRF: No token, state change
    return 'Profile updated!'

# REAL VULNERABILITY: JWT Tampering
@app.route('/jwt', methods=['POST'])
@log_benchmark("Real Vulnerability")
def jwt_vuln():
    # JWT Tampering: Accepts unsigned/weakly signed JWTs
    token = request.form.get('token', '')
    try:
        data = jwt.decode(token, options={"verify_signature": False})
        return f"JWT data: {data}"
    except Exception as e:
        return str(e), 400

# --- False Positives ---

# FALSE POSITIVE: XSS (Proper Escaping)
@app.route('/safe-echo')
@log_benchmark("False Positive")
def safe_echo():
    user_input = request.args.get('input', '')
    return render_template('safe_echo.html', user_input=user_input)

# FALSE POSITIVE: XSS (Commented Script)
@app.route('/commented-xss')
@log_benchmark("False Positive")
def commented_xss():
    return render_template('commented_xss.html')

# FALSE POSITIVE: JS Injection (Static Template)
@app.route('/js-template')
@log_benchmark("False Positive")
def js_template():
    return send_from_directory('static', 'template.js')

# FALSE POSITIVE: SQLi (Safe Parameterized Logging)
@app.route('/sql-logging')
@log_benchmark("False Positive")
def sql_logging():
    q = request.args.get('q', '')
    query = "SELECT * FROM users WHERE name = ?"
    return f"SQL: {query} with param: {q}"

# FALSE POSITIVE: SQLi (String Echo)
@app.route('/sql-string-echo')
@log_benchmark("False Positive")
def sql_string_echo():
    q = request.args.get('q', 'admin')
    return f"SELECT * FROM users WHERE name = '{q}'"

# FALSE POSITIVE: Path Traversal (Sanitized)
@app.route('/static-viewer')
@log_benchmark("False Positive")
def static_viewer():
    filename = request.args.get('file', '')
    safe_name = secure_filename(filename)
    return f"Requested: {escape(filename)} (sanitized: {safe_name})"

# FALSE POSITIVE: Path Traversal (Whitelisted)
@app.route('/view-log')
@log_benchmark("False Positive")
def view_log():
    filename = request.args.get('file', 'access.log')
    if filename not in ['access.log', 'error.log']:
        abort(403)
    return f"Log content for {filename}: ... (static)"

# FALSE POSITIVE: CSRF (Backend Auth Required)
@app.route('/simulate-form', methods=['GET', 'POST'])
@log_benchmark("False Positive")
def simulate_form():
    if request.method == 'POST':
        if request.cookies.get('auth') != '1':
            return 'Forbidden', 403
        return 'Form submitted!'
    return render_template('simulate_form.html')

# FALSE POSITIVE: File Upload (Not Saved)
@app.route('/upload-dummy', methods=['GET', 'POST'])
@log_benchmark("False Positive")
def upload_dummy():
    msg = ''
    if request.method == 'POST':
        _ = request.files['file']
        msg = 'File accepted (not saved).'
    return render_template('upload_dummy.html', msg=msg)

# FALSE POSITIVE: Open Redirect (Preview Only)
@app.route('/redirect-preview')
@log_benchmark("False Positive")
def redirect_preview():
    next_url = request.args.get('next', '/')
    return render_template('redirect_preview.html', next_url=next_url)

# --- Error Handling ---
@app.errorhandler(Exception)
def handle_exception(e):
    # Improper error handling: show stacktrace
    import traceback
    return f"<pre>{traceback.format_exc()}</pre>", 500

# --- CSP Header (missing on purpose) ---
# No CSP header set

# --- Logging and Benchmarking Utilities ---
import logging
import datetime
import functools
import json

BENCHMARK_LOG = 'benchmark.log'
SCANNER_LOG = 'scanner_results.log'

# Logging decorator for benchmark data
# Each endpoint is decorated with @log_benchmark(label="Real Vulnerability" or "False Positive")
def log_benchmark(label):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            req_data = {
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'endpoint': request.path,
                'method': request.method,
                'url': request.url,
                'headers': dict(request.headers),
                'args': request.args.to_dict(),
                'form': request.form.to_dict(),
                'json': request.get_json(silent=True),
                'data': request.get_data(as_text=True)
            }
            response = func(*args, **kwargs)
            # Flask may return string, tuple, or Response
            if isinstance(response, tuple):
                resp_obj = app.make_response(response[0])
                status = response[1] if len(response) > 1 else 200
            else:
                resp_obj = app.make_response(response)
                status = resp_obj.status_code
            # Add standardized header
            resp_obj.headers['X-Benchmark-Endpoint'] = f"{request.path} [{label}]"
            # Log response
            resp_data = {
                'status': status,
                'headers': dict(resp_obj.headers),
                'body': resp_obj.get_data(as_text=True)
            }
            log_entry = {
                'request': req_data,
                'response': resp_data,
                'vulnerability_label': label
            }
            with open(BENCHMARK_LOG, 'a') as logf:
                logf.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            return resp_obj
        return wrapper
    return decorator

# Endpoint for scanner result integration
@app.route('/log-scanner-result', methods=['POST'])
def log_scanner_result():
    data = request.get_json(force=True)
    with open(SCANNER_LOG, 'a') as logf:
        logf.write(json.dumps(data, ensure_ascii=False) + '\n')
    return {'status': 'ok'}, 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
