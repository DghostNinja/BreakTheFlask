from flask import Flask, request, jsonify, make_response, redirect
import jwt
import hashlib
import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

JWT_SECRET = "supersecret"
ENCRYPTION_KEY = b"ThisIsA16ByteKey"

def encrypt_ecb(data):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    padded = pad(data.encode(), 16)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()

def decrypt_ecb(data):
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_ECB)
    decoded = base64.b64decode(data)
    decrypted = unpad(cipher.decrypt(decoded), 16)
    return decrypted.decode()

@app.route("/")
def index():
    return """<h2>Crypto Failures Lab</h2><ul>
        <li><a href='/login'>/login</a></li>
        <li><a href='/store_secret'>/store_secret</a></li>
        <li><a href='/view_secret?data=...</a></li>
        <li><a href='/reset_password?email=test@example.com'>/reset_password</a></li>
        <li><a href='/log?secret=1234'>/log</a></li>
        <li><a href='/auth_required'>/auth_required</a></li>
        <li><a href='/download/flag.txt?token=...'>/download/flag.txt</a></li>
        <li><a href='/cookie_test'>/cookie_test</a></li>
    </ul>"""

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        token = jwt.encode({"user": username}, JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})
    return '''<form method="post">
        Username: <input name="username"><br>
        <button type="submit">Login</button></form>'''

@app.route("/auth_required")
def auth_required():
    token = request.headers.get("Authorization")
    if not token:
        return "Missing token", 401
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return f"Welcome {decoded['user']}!"
    except Exception as e:
        return f"Invalid token: {str(e)}", 403

@app.route("/store_secret", methods=["GET", "POST"])
def store_secret():
    if request.method == "POST":
        secret = request.form.get("secret")
        encrypted = encrypt_ecb(secret)
        return f"Encrypted secret: {encrypted}"
    return '''<form method="post">
        Secret: <input name="secret"><br>
        <button type="submit">Encrypt</button></form>'''

@app.route("/view_secret")
def view_secret():
    encrypted = request.args.get("data")
    try:
        decrypted = decrypt_ecb(encrypted)
        return f"Decrypted: {decrypted}"
    except:
        return "Failed to decrypt."

@app.route("/reset_password")
def reset():
    email = request.args.get("email")
    token = hashlib.md5((email + str(int(time.time()))).encode()).hexdigest()
    return f"Reset link: /reset_form?token={token}"

@app.route("/log")
def log():
    secret = request.args.get("secret")
    print(f"LOGGED: {secret}")
    return "Logged."

@app.route("/cookie_test")
def cookie_test():
    token = jwt.encode({"user": "admin"}, JWT_SECRET, algorithm="HS256")
    resp = make_response("Cookie set!")
    resp.set_cookie("auth_token", token, httponly=False, secure=False)
    return resp

@app.route("/download/<filename>")
def download(filename):
    token = request.args.get("token")
    if token != "letmein":
        return "Invalid download token", 403
    return f"Fake file: {filename}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
