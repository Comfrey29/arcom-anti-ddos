# server.py
import os
import hmac
import hashlib
import secrets
import json
from datetime import datetime, timedelta

from flask import Flask, request, render_template_string, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# -----------------------
# CONFIG
# -----------------------
DB_PATH = os.environ.get("DATABASE_URL", "sqlite:///arcom_central.db")
APP_SECRET = os.environ.get("APP_SECRET", "change-me-to-a-long-secret")
REQUIRED_ADMIN_APPROVALS = int(os.environ.get("REQUIRED_ADMIN_APPROVALS", "2"))  # K multisig
BLACKLIST_TIMEOUT_HOURS = int(os.environ.get("BLACKLIST_TIMEOUT_HOURS", "24"))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = APP_SECRET

db = SQLAlchemy(app)

# -----------------------
# MODELS
# -----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="guest")  # 'admin' or 'guest'

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), unique=True, nullable=False)  # public id
    name = db.Column(db.String(120))
    owner_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    owner_accepted = db.Column(db.Boolean, default=False)  # owner must accept linkage
    secret = db.Column(db.String(128), nullable=False)  # shared secret (hex)
    blocked = db.Column(db.Boolean, default=False)  # local block flag
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DisableRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), nullable=False)
    requested_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.String(500))
    status = db.Column(db.String(20), default="pending")  # pending, approved, executed, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approvals = db.Column(db.Text, default="[]")  # JSON list of user ids who approved
    executed_at = db.Column(db.DateTime, nullable=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(64), nullable=True)
    ip = db.Column(db.String(64))
    details = db.Column(db.String(1000))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -----------------------
# HELPERS
# -----------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return redirect(url_for("login"))
        u = User.query.get(uid)
        if not u or u.role != "admin":
            flash("Admin privileges required.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

def sign_command(client_secret_hex: str, payload_json: str) -> str:
    """Sign payload using HMAC-SHA256 with client secret (hex). Return hex signature."""
    key = bytes.fromhex(client_secret_hex)
    return hmac.new(key, payload_json.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_signature(client_secret_hex: str, payload_json: str, signature_hex: str) -> bool:
    key = bytes.fromhex(client_secret_hex)
    expected = hmac.new(key, payload_json.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)

# -----------------------
# ADMIN / USER UI (minimal HTML templates inlined for prototype)
# -----------------------
INDEX_HTML = """
<!doctype html>
<title>ArCom Central</title>
<h1>ArCom Central</h1>
{% if user %}
  <p>Benvingut, {{ user.username }} ({{ user.role }})</p>
  <p><a href="{{ url_for('logout') }}">Logout</a></p>
  <ul>
    <li><a href="{{ url_for('clients') }}">Clients</a></li>
    <li><a href="{{ url_for('reports') }}">Reports</a></li>
    {% if user.role == 'admin' %}
      <li><a href="{{ url_for('admin_disable_requests') }}">Disable requests (admin)</a></li>
    {% endif %}
  </ul>
{% else %}
  <p><a href="{{ url_for('login') }}">Login</a> | <a href="{{ url_for('register') }}">Register</a></p>
{% endif %}
"""

# Other minimal templates omitted for brevity — use basic Flask render_template_string where needed.

# -----------------------
# ROUTES: AUTH
# -----------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        pw = request.form["password"]
        role = request.form.get("role", "guest")
        if User.query.filter_by(username=username).first():
            flash("User exists", "danger")
            return redirect(url_for("register"))
        u = User(username=username, password_hash=generate_password_hash(pw), role=role)
        db.session.add(u)
        db.session.commit()
        flash("User created", "success")
        return redirect(url_for("login"))
    return render_template_string("""
    <h2>Register</h2>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      Role: <select name="role"><option>guest</option><option>admin</option></select><br>
      <input type="submit" value="Create">
    </form>
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        pw = request.form["password"]
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(pw):
            session["user_id"] = u.id
            flash("Logged in", "success")
            return redirect(url_for("index"))
        flash("Invalid", "danger")
    return render_template_string("""
    <h2>Login</h2>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit" value="Login">
    </form>
    """)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# -----------------------
# ROUTES: MAIN UI
# -----------------------
@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = User.query.get(session["user_id"])
    return render_template_string(INDEX_HTML, user=user)

@app.route("/clients")
@login_required
def clients():
    user = User.query.get(session["user_id"])
    if user.role == "admin":
        clients = Client.query.order_by(Client.created_at.desc()).all()
    else:
        clients = Client.query.filter_by(owner_user_id=user.id).all()
    out = "<h2>Clients</h2><a href='/'>Back</a><ul>"
    for c in clients:
        out += f"<li>{c.client_id} — {c.name} — owner_accepted={c.owner_accepted} — blocked={c.blocked}"
        out += f" — <a href='/client/{c.client_id}'>view</a></li>"
    out += "</ul>"
    return out

@app.route("/client/<cid>")
@login_required
def client_view(cid):
    c = Client.query.filter_by(client_id=cid).first_or_404()
    return f"<h2>Client {c.client_id}</h2><pre>Name: {c.name}\\nOwner accepted: {c.owner_accepted}\\nBlocked: {c.blocked}</pre><a href='/clients'>Back</a>"

@app.route("/reports")
@login_required
def reports():
    rs = Report.query.order_by(Report.created_at.desc()).limit(200).all()
    out = "<h2>Reports</h2><a href='/'>Back</a><ul>"
    for r in rs:
        out += f"<li>{r.created_at} — client:{r.client_id} ip:{r.ip} — {r.details}</li>"
    out += "</ul>"
    return out

# -----------------------
# ADMIN: disable request flow
# -----------------------
@app.route("/admin/disable_requests")
@admin_required
def admin_disable_requests():
    reqs = DisableRequest.query.order_by(DisableRequest.created_at.desc()).all()
    out = "<h2>Disable Requests</h2><a href='/'>Back</a><ul>"
    for rq in reqs:
        approvals = json.loads(rq.approvals)
        out += (f"<li>#{rq.id} client:{rq.client_id} status:{rq.status} by:{rq.requested_by} "
                f"approvals:{len(approvals)} reason:{rq.reason} "
                f"<a href='/admin/approve/{rq.id}'>Approve</a></li>")
    out += "</ul>"
    return out

@app.route("/admin/request_disable", methods=["POST"])
@admin_required
def admin_request_disable():
    client_id = request.form["client_id"]
    reason = request.form.get("reason", "")
    uid = session["user_id"]
    c = Client.query.filter_by(client_id=client_id).first()
    if not c:
        flash("Client not found", "danger")
        return redirect(url_for("admin_disable_requests"))
    rq = DisableRequest(client_id=client_id, requested_by=uid, reason=reason)
    db.session.add(rq)
    db.session.commit()
    flash("Disable requested", "success")
    return redirect(url_for("admin_disable_requests"))

@app.route("/admin/approve/<int:req_id>")
@admin_required
def admin_approve(req_id):
    uid = session["user_id"]
    rq = DisableRequest.query.get_or_404(req_id)
    if rq.status != "pending":
        flash("Request not pending", "warning")
        return redirect(url_for("admin_disable_requests"))
    approvals = json.loads(rq.approvals)
    if uid in approvals:
        flash("You already approved", "info")
        return redirect(url_for("admin_disable_requests"))
    approvals.append(uid)
    rq.approvals = json.dumps(approvals)
    # if enough approvals, mark as approved and prepare execution
    if len(approvals) >= REQUIRED_ADMIN_APPROVALS:
        rq.status = "approved"
        # at approval moment, we'll create execution record; clients will poll commands endpoint
    db.session.commit()
    flash("Approved", "success")
    return redirect(url_for("admin_disable_requests"))

# -----------------------
# API: Client registration / commands / reports
# -----------------------
@app.route("/api/client/register", methods=["POST"])
def api_client_register():
    """
    Client initiates registration:
    POST JSON: { "client_id": "my-server-1", "name": "My Server", "owner_username": "bob" }
    Response: { "client_id": "...", "secret": "hexsecret" }  (secret must be saved by client)
    Note: owner_username must match an existing user and that user must consent/accept linkage in UI.
    """
    data = request.json or {}
    cid = data.get("client_id") or secrets.token_hex(8)
    name = data.get("name", "")
    owner_username = data.get("owner_username")
    owner = None
    if owner_username:
        owner = User.query.filter_by(username=owner_username).first()
    # create secret
    secret = secrets.token_hex(32)  # 256-bit secret
    if Client.query.filter_by(client_id=cid).first():
        return jsonify({"error": "client_id exists"}), 400
    c = Client(client_id=cid, name=name, owner_user_id=(owner.id if owner else None), secret=secret, owner_accepted=False)
    db.session.add(c)
    db.session.commit()
    # Notify owner (in prod, send email/webhook). Here we just return and admin/owner must accept via UI.
    return jsonify({"client_id": cid, "secret": secret, "note": "owner must accept linkage in web UI"})

@app.route("/api/report", methods=["POST"])
def api_report():
    """
    Client or any reporter can send a report about an attacking IP
    Headers: Authorization: Bearer <client_id>:<secret>   OR none (if trusted)
    Body: {"ip":"1.2.3.4", "details":"..."}
    """
    auth = request.headers.get("Authorization", "")
    client = None
    if auth.startswith("Bearer "):
        token = auth.split(" ",1)[1]
        # expect token as client_id:secret
        try:
            cid, secret = token.split(":",1)
            client = Client.query.filter_by(client_id=cid).first()
            if not client or not secrets.compare_digest(client.secret, secret):
                client = None
        except Exception:
            client = None
    data = request.json or {}
    ip = data.get("ip")
    details = data.get("details","")
    if not ip:
        return jsonify({"error":"no ip"}), 400
    r = Report(client_id=(client.client_id if client else None), ip=ip, details=details)
    db.session.add(r)
    db.session.commit()
    # Optionally add IP to global blacklist if many reports — for prototype we don't auto-add.
    return jsonify({"status":"ok"})

@app.route("/api/blacklist", methods=["GET"])
def api_blacklist():
    """
    Return current blacklist (computed from DisableRequests with status approved/executed)
    Clients poll this to update local nftables/iptables sets.
    Authentication: optional token header for security (not required here).
    """
    # for prototype: blacklist comes from DisableRequest for clients that are problematic OR explicit admin lists
    # Build a list: if a client has been disabled, include its client_id? In our design we want to block *attacker IPs*,
    # but also we may want to mark certain clients as blocked. We'll return both structures.
    blocked_clients = [c.client_id for c in Client.query.filter_by(blocked=True).all()]
    # also collect reported IPs in last X hours and count
    cutoff = datetime.utcnow() - timedelta(hours=BLACKLIST_TIMEOUT_HOURS)
    ips = db.session.query(Report.ip, db.func.count(Report.id).label("cnt")).filter(Report.created_at >= cutoff).group_by(Report.ip).having(db.func.count(Report.id) >= 1).all()
    ip_list = [ip for ip, cnt in ips]
    return jsonify({"blocked_clients": blocked_clients, "suspicious_ips": ip_list})

@app.route("/api/commands", methods=["GET"])
def api_commands():
    """
    Client polls here to get any signed command.
    Auth: Authorization: Bearer <client_id>:<secret>
    Response: { "commands": [ { "payload": {...}, "signature": "..." } ] }
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error":"auth required"}), 401
    token = auth.split(" ",1)[1]
    try:
        cid, secret = token.split(":",1)
    except Exception:
        return jsonify({"error":"bad token"}), 401
    client = Client.query.filter_by(client_id=cid).first()
    if not client or not secrets.compare_digest(client.secret, secret):
        return jsonify({"error":"invalid credentials"}), 401

    # Find disable requests that are approved and not yet executed for this client
    pending = DisableRequest.query.filter_by(client_id=cid, status="approved").all()
    commands = []
    for rq in pending:
        payload = {
            "cmd": "disable_client",
            "client_id": cid,
            "request_id": rq.id,
            "timestamp": datetime.utcnow().isoformat(),
            "reason": rq.reason
        }
        payload_json = json.dumps(payload, sort_keys=True)
        signature = sign_command(client.secret, payload_json)
        commands.append({"payload": payload, "signature": signature})
        # mark as executed (so we don't re-issue)
        rq.status = "executed"
        rq.executed_at = datetime.utcnow()
        # option: set client.blocked True so it is in other APIs
        client.blocked = True
        db.session.commit()
    return jsonify({"commands": commands})

# -----------------------
# UTIL: init DB route (only for dev) - remove/secure in prod
# -----------------------
@app.route("/init_db")
def init_db():
    db.create_all()
    return "OK"

# -----------------------
# RUN
# -----------------------
if __name__ == "__main__":
    db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
