# Secure Password Manager – FastAPI + Encrypted Vault
# Run: python main.py

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from cryptography.fernet import Fernet
import sqlite3
import os

# ---------- Security ----------
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    cipher = Fernet(f.read())

# ---------- App ----------
app = FastAPI()

# ---------- Database ----------
conn = sqlite3.connect("vault.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT,
    username TEXT,
    password TEXT
)
""")
conn.commit()

# ---------- Templates ----------
templates = Jinja2Templates(directory="templates")

# ---------- Routes ----------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    cursor.execute("SELECT * FROM passwords")
    rows = cursor.fetchall()

    decrypted = []
    for r in rows:
        decrypted.append((r[0], r[1], r[2], cipher.decrypt(r[3]).decode()))

    return templates.TemplateResponse("index.html", {
        "request": request,
        "passwords": decrypted
    })

@app.post("/add")
def add_password(
    service: str = Form(...),
    username: str = Form(...),
    password: str = Form(...)
):
    encrypted = cipher.encrypt(password.encode())
    cursor.execute(
        "INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
        (service, username, encrypted)
    )
    conn.commit()
    return RedirectResponse("/", status_code=303)

@app.get("/delete/{pid}")
def delete_password(pid: int):
    cursor.execute("DELETE FROM passwords WHERE id=?", (pid,))
    conn.commit()
    return RedirectResponse("/", status_code=303)

# ---------- Run ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)


# -----------------------------
# Create folder: templates/
# Create file: templates/index.html
# -----------------------------

"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Password Vault</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;500;700&display=swap" rel="stylesheet">
<style>
body {
  font-family: Inter, sans-serif;
  background: radial-gradient(circle at top, #020617, #000);
  color: #e5e7eb;
  margin: 0;
  padding: 40px;
}
.container {
  max-width: 900px;
  margin: auto;
}
h1 { font-size: 2.3rem; }
.card {
  background: rgba(2,6,23,.85);
  border-radius: 18px;
  padding: 24px;
  box-shadow: 0 25px 50px rgba(0,0,0,.7);
  margin-bottom: 24px;
}
form {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr auto;
  gap: 12px;
}
input, button {
  padding: 12px;
  border-radius: 10px;
  border: none;
  font-size: 14px;
}
input {
  background: #020617;
  border: 1px solid #1e293b;
  color: white;
}
button {
  background: #22c55e;
  color: #022c22;
  font-weight: 700;
  cursor: pointer;
}
button:hover { background: #16a34a; }
table {
  width: 100%;
  border-collapse: collapse;
}
th, td {
  padding: 14px;
  border-bottom: 1px solid #1e293b;
}
.password {
  font-family: monospace;
  letter-spacing: 1px;
}
.delete {
  color: #f87171;
  font-weight: bold;
  text-decoration: none;
}
.copy {
  color: #60a5fa;
  cursor: pointer;
}
</style>
<script>
function copyText(text) {
  navigator.clipboard.writeText(text);
  alert('Password copied to clipboard');
}
</script>
</head>
<body>
<div class="container">
<h1>🔐 Secure Password Vault</h1>

<div class="card">
<form method="post" action="/add">
  <input name="service" placeholder="Service (e.g. Gmail)" required>
  <input name="username" placeholder="Username / Email" required>
  <input name="password" placeholder="Password" required>
  <button>Add</button>
</form>
</div>

<div class="card">
<table>
<tr>
  <th>Service</th><th>Username</th><th>Password</th><th></th>
</tr>
{% for p in passwords %}
<tr>
  <td>{{ p[1] }}</td>
  <td>{{ p[2] }}</td>
  <td class="password">•••••••• <span class="copy" onclick="copyText('{{ p[3] }}')">📋</span></td>
  <td><a class="delete" href="/delete/{{ p[0] }}">✕</a></td>
</tr>
{% endfor %}
</table>
</div>
</div>
</body>
</html>
"""
