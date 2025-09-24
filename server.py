from flask import Flask, render_template, request, redirect, url_for, flash, session
import json, os

app = Flask(__name__)
app.secret_key = "arcom-central-secret"  # Canviar per un secret segur

USERS_FILE = "users.json"

# Inicialitza fitxer de usuaris
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump([], f)

# Funcions auxiliars
def load_users():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def save_user(user):
    users = load_users()
    users.append(user)
    save_users(users)

def get_user(username):
    users = load_users()
    for u in users:
        if u["username"] == username:
            return u
    return None

def mark_admin_inactive(username, reason="No compleix polítiques"):
    users = load_users()
    for u in users:
        if u["username"] == username and u["role"] == "administrator":
            u["active"] = False
            u["expulsion_reason"] = reason
            save_users(users)
            return True
    return False

# Rutes principals
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/policies")
def policies():
    return render_template("policies.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        role = request.form.get("role")
        if not username or not role:
            flash("Tots els camps són obligatoris!", "error")
            return redirect(url_for("register"))
        # Evita duplicats
        if get_user(username):
            flash("Nom d'usuari ja existeix!", "error")
            return redirect(url_for("register"))
        # Guarda usuari
        save_user({"username": username, "role": role, "active": True})
        flash(f"Usuari {username} creat correctament!", "success")
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/interests")
def interests():
    return render_template("interests.html")

# Login simple per mostrar dashboard segons rol
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        user = get_user(username)
        if user:
            session["username"] = username
            session["role"] = user["role"]
            session["active"] = user.get("active", True)
            flash(f"Benvingut {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Usuari no trobat!", "error")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        flash("Has de fer login primer!", "error")
        return redirect(url_for("login"))
    username = session["username"]
    role = session["role"]
    active = session.get("active", True)
    return render_template("dashboard.html", username=username, role=role, active=active)

# Expulsió d'administradors (només Owner pot fer-ho)
@app.route("/expel_admin/<username>")
def expel_admin(username):
    if session.get("role") != "owner":
        flash("Només l'Owner pot expulsar administradors!", "error")
        return redirect(url_for("dashboard"))
    if mark_admin_inactive(username):
        flash(f"Administrador {username} expulsat correctament!", "success")
    else:
        flash("Administrador no trobat o ja inactiu!", "error")
    return redirect(url_for("dashboard"))

# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("Sessió tancada correctament!", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
