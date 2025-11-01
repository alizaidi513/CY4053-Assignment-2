"""
secure_app.py
Streamlit Secure FinTech Mini App for CY4053 Assignment 2
Features:
- Registration & Login (bcrypt hashed passwords)
- Password strength validation
- Session management using st.session_state
- Encrypted secure note with cryptography.Fernet
- Audit logs stored in SQLite
- Profile update, simulated transfer, file upload with validation
- Basic protections against common input issues; generic error messages
"""

import os
import re
import sqlite3
import datetime
import html
from pathlib import Path

import streamlit as st
import bcrypt
from cryptography.fernet import Fernet
from email_validator import validate_email, EmailNotValidError

# ---------- Config ----------
BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "secure_app.db"
KEY_FILE = BASE_DIR / "secret.key"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
ALLOWED_EXT = {"png", "jpg", "jpeg", "pdf"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB

st.set_page_config(page_title="Secure FinTech App", layout="wide")

# ---------- Encryption key ----------
if not KEY_FILE.exists():
    KEY_FILE.write_bytes(Fernet.generate_key())
FERNET = Fernet(KEY_FILE.read_bytes())

# ---------- Helper / DB utilities ----------
def get_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            created_at TEXT NOT NULL,
            enc_note BLOB,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            ip TEXT,
            ts TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            saved_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_action(action, user_id=None):
    try:
        conn = get_conn()
        c = conn.cursor()
        ip = st.runtime.get_client().ip if hasattr(st.runtime, "get_client") else "local"
        c.execute("INSERT INTO logs (user_id, action, ip, ts) VALUES (?, ?, ?, ?)",
                  (user_id, action, ip, datetime.datetime.utcnow().isoformat()))
        conn.commit()
    except Exception:
        # do not crash app on logging failure
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

# ---------- Validation helpers ----------
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,40}$')

def validate_username(u):
    if not u or not USERNAME_RE.match(u):
        return False, "Username must be 3-40 chars long, letters/numbers/._- only."
    return True, ""

def validate_password_strength(pw):
    if len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'\d', pw):
        return False, "Password must include a number."
    if not re.search(r'[A-Z]', pw):
        return False, "Password must include an uppercase letter."
    if not re.search(r'[^\w\s]', pw):
        return False, "Password must include a symbol (e.g., !@#$%)."
    return True, ""

def validate_email_addr(email):
    try:
        validate_email(email)
        return True, ""
    except EmailNotValidError as e:
        return False, str(e)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def sanitize_input(s: str):
    # escape HTML to avoid reflected XSS in outputs
    return html.escape(s or "")

# ---------- Auth helpers ----------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), pw_hash)

def get_user_by_username_or_email(identifier):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? OR email=?", (identifier, identifier))
    row = c.fetchone()
    conn.close()
    return row

def create_user(username, email, password):
    pw_hash = hash_password(password)
    conn = get_conn()
    c = conn.cursor()
    now = datetime.datetime.utcnow().isoformat()
    try:
        c.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                  (username, email, pw_hash, now))
        conn.commit()
        user_id = c.lastrowid
        log_action("register", user_id)
        return True, ""
    except sqlite3.IntegrityError as e:
        return False, "Username or email already exists."
    finally:
        conn.close()

def update_failed_attempts(user_id, reset=False):
    conn = get_conn()
    c = conn.cursor()
    if reset:
        c.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user_id,))
    else:
        c.execute("UPDATE users SET failed_attempts=failed_attempts+1 WHERE id=?", (user_id,))
        c.execute("SELECT failed_attempts FROM users WHERE id=?", (user_id,))
        fa = c.fetchone()["failed_attempts"]
        # lock for 10 minutes after 5 failed attempts
        if fa >= 5:
            lock_until = (datetime.datetime.utcnow() + datetime.timedelta(minutes=10)).isoformat()
            c.execute("UPDATE users SET locked_until=? WHERE id=?", (lock_until, user_id))
    conn.commit()
    conn.close()

def is_locked(user_row):
    lu = user_row["locked_until"]
    if lu:
        try:
            if datetime.datetime.fromisoformat(lu) > datetime.datetime.utcnow():
                return True
        except Exception:
            return False
    return False

# ---------- Initialize DB ----------
init_db()

# ---------- UI: helpers ----------
def require_login():
    if "user_id" not in st.session_state:
        st.warning("You must log in to access this page.")
        st.stop()

def current_user_row():
    if "user_id" not in st.session_state:
        return None
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (st.session_state["user_id"],))
    row = c.fetchone()
    conn.close()
    return row

# ---------- App pages ----------
def page_home():
    st.title("Secure FinTech App (Streamlit) — CY4053 Assignment 2")
    st.markdown(
        """
        This mini app demonstrates secure features you can test manually:
        - Register / Login (bcrypt hashed passwords)
        - Password strength enforcement
        - Encrypted secure note (Fernet)
        - Profile update, simulated transfers (logged)
        - File upload validation (png/jpg/pdf, 2MB)
        - Audit logs of actions
        """
    )

def page_register():
    st.header("Register")
    with st.form("register_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm password", type="password")
        submitted = st.form_submit_button("Register")

    if submitted:
        ok, msg = validate_username(username)
        if not ok:
            st.error(msg); return
        ok, msg = validate_email_addr(email)
        if not ok:
            st.error(msg); return
        ok, msg = validate_password_strength(password)
        if not ok:
            st.error(msg); return
        if password != confirm:
            st.error("Passwords do not match."); return

        ok, msg = create_user(username.strip(), email.strip(), password)
        if ok:
            st.success("Registration successful — please login.")
        else:
            st.error("Registration failed: " + msg)

def page_login():
    st.header("Login")
    with st.form("login_form"):
        identifier = st.text_input("Username or Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
    if submitted:
        if not identifier or not password:
            st.error("Provide both username/email and password."); return
        row = get_user_by_username_or_email(identifier.strip())
        if not row:
            log_action("failed_login", None)
            st.error("Invalid credentials.")
            return
        if is_locked(row):
            st.error("Account is locked due to multiple failed attempts. Try later.")
            return
        pw_hash = row["password_hash"]
        # pw_hash stored as bytes; sqlite returns as bytes
        try:
            if check_password(password, pw_hash):
                # successful login
                st.session_state["user_id"] = row["id"]
                st.session_state["username"] = row["username"]
                update_failed_attempts(row["id"], reset=True)
                log_action("login", row["id"])
                st.success(f"Logged in as {row['username']}")
            else:
                update_failed_attempts(row["id"], reset=False)
                log_action("failed_login", row["id"])
                st.error("Invalid credentials.")
        except Exception:
            st.error("Login error (generic).")

def page_logout():
    if "user_id" in st.session_state:
        uid = st.session_state.pop("user_id")
        st.session_state.pop("username", None)
        log_action("logout", uid)
        st.success("Logged out.")
    else:
        st.info("Not logged in.")

def page_dashboard():
    require_login()
    row = current_user_row()
    st.header(f"Dashboard — {sanitize_input(row['username'])}")
    st.write("Account created at:", row["created_at"])

    # Secure Note (encrypt/decrypt)
    st.subheader("Secure Note (encrypted in DB)")
    with st.form("note_form"):
        note = st.text_area("Enter secure note (max 1000 chars)", value="")
        save_note = st.form_submit_button("Save Note (encrypted)")
    if save_note:
        if len(note) > 1000:
            st.error("Note too long.")
        else:
            try:
                enc = FERNET.encrypt(note.encode())
                conn = get_conn()
                c = conn.cursor()
                c.execute("UPDATE users SET enc_note=? WHERE id=?", (enc, row["id"]))
                conn.commit()
                conn.close()
                log_action("save_note", row["id"])
                st.success("Secure note encrypted & saved.")
            except Exception:
                st.error("Could not save note (generic).")

    if row["enc_note"]:
        if st.button("View decrypted secure note"):
            try:
                dec = FERNET.decrypt(row["enc_note"]).decode()
            except Exception:
                dec = "[decryption failed]"
            log_action("view_note", row["id"])
            st.code(dec)

    st.subheader("Simulate Transfer")
    with st.form("transfer_form"):
        to_account = st.text_input("To Account (digits and - only)")
        amount = st.text_input("Amount (e.g., 150.50)")
        transfer = st.form_submit_button("Simulate Transfer")
    if transfer:
        # basic validation
        if not re.fullmatch(r'^[0-9-]+$', to_account or ""):
            st.error("Invalid account format; use digits and hyphen only.")
        else:
            try:
                amt = float(amount)
                if amt <= 0:
                    st.error("Amount must be > 0.")
                else:
                    log_action(f"transfer {amt} to {sanitize_input(to_account)}", row["id"])
                    st.success("Transfer simulated and logged.")
            except ValueError:
                st.error("Invalid amount.")

def page_profile():
    require_login()
    row = current_user_row()
    st.header("Profile")
    with st.form("profile_form"):
        email = st.text_input("Email", value=row["email"])
        submit = st.form_submit_button("Update Profile")
    if submit:
        ok, msg = validate_email_addr(email)
        if not ok:
            st.error(msg); return
        try:
            conn = get_conn()
            c = conn.cursor()
            c.execute("UPDATE users SET email=? WHERE id=?", (email.strip(), row["id"]))
            conn.commit()
            conn.close()
            log_action("profile_update", row["id"])
            st.success("Profile updated.")
        except sqlite3.IntegrityError:
            st.error("Email already in use.")
        except Exception:
            st.error("Could not update profile (generic).")

def page_upload():
    require_login()
    row = current_user_row()
    st.header("File Upload (png, jpg, jpeg, pdf) — max 2MB")
    uploaded = st.file_uploader("Choose file", type=list(ALLOWED_EXT))
    if uploaded is not None:
        # size check
        buf = uploaded.getbuffer()
        if len(buf) > MAX_UPLOAD_BYTES:
            st.error("File too large (max 2MB).")
            log_action("upload_blocked_large", row["id"])
        else:
            filename = sanitize_input(uploaded.name)
            if not allowed_file(filename):
                st.error("File type not allowed.")
                log_action("upload_blocked_type", row["id"])
            else:
                save_path = UPLOAD_DIR / f"{row['id']}_{int(datetime.datetime.utcnow().timestamp())}_{filename}"
                try:
                    with open(save_path, "wb") as f:
                        f.write(buf)
                    conn = get_conn()
                    c = conn.cursor()
                    c.execute("INSERT INTO uploads (user_id, filename, saved_at) VALUES (?, ?, ?)",
                              (row["id"], str(save_path.name), datetime.datetime.utcnow().isoformat()))
                    conn.commit()
                    conn.close()
                    log_action(f"file_upload {save_path.name}", row["id"])
                    st.success("File uploaded successfully.")
                except Exception:
                    st.error("Failed to save file (generic).")

    st.markdown("**Uploaded files:**")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT filename, saved_at FROM uploads WHERE user_id=? ORDER BY id DESC LIMIT 20", (row["id"],))
    files = c.fetchall()
    conn.close()
    for f in files:
        st.write(f"{f['saved_at']} — {f['filename']}")

def page_logs():
    require_login()
    st.header("Audit Logs (last 200)")
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 200")
    rows = c.fetchall()
    conn.close()
    if not rows:
        st.write("No logs.")
        return
    # display table
    for r in rows:
        st.text(f"{r['ts']} | user:{r['user_id'] or 'anon'} | {r['action']} | ip:{r['ip']}")

# ---------- Navigation / main ----------
PAGES = {
    "Home": page_home,
    "Register": page_register,
    "Login": page_login,
    "Dashboard": page_dashboard,
    "Profile": page_profile,
    "Upload": page_upload,
    "Logs": page_logs,
    "Logout": page_logout
}

# Ensure session defaults
if "user_id" not in st.session_state:
    st.session_state["user_id"] = None
if "username" not in st.session_state:
    st.session_state["username"] = None

# Sidebar navigation
st.sidebar.title("Navigation")
page_choice = st.sidebar.selectbox("Go to", list(PAGES.keys()), index=0)

# show basic info
if st.session_state["user_id"]:
    st.sidebar.markdown(f"**Logged in as:** {st.session_state.get('username')}")
    if st.sidebar.button("Logout"):
        page_logout()

# Run selected page
try:
    PAGES[page_choice]()
except Exception as e:
    # Generic error handling — do not leak stack trace
    st.error("An unexpected error occurred. (generic)")
    log_action("server_error", st.session_state.get("user_id"))

# Footer info
st.sidebar.markdown("---")
st.sidebar.markdown("Assignment: Build & manually test this app for cybersecurity (20+ tests).")
