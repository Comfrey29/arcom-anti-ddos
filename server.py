import os
import json
from flask import Flask, request, jsonify
from datetime import datetime, timedelta

app = Flask(__name__)

# -------------------------
# CONFIGURACIÓ
# -------------------------
AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "SECRET_TOKEN")  # Token d'autenticació
BLACKLIST_FILE = "blacklist.json"                          # Fitxer de persistència
BLACKLIST_TIMEOUT_HOURS = 24                                # Expiració d'IPs en hores

# -------------------------
# CARREGAR BLACKLIST EXISTENT
# -------------------------
if os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, "r") as f:
        blacklist_global = json.load(f)
        # Convertir timestamps de string a datetime
        for ip in blacklist_global:
            blacklist_global[ip] = datetime.fromisoformat(blacklist_global[ip])
else:
    blacklist_global = {}

# -------------------------
# FUNCIONS AUXILIARS
# -------------------------
def save_blacklist():
    """Guarda la blacklist al fitxer en format JSON"""
    with open(BLACKLIST_FILE, "w") as f:
        json.dump({ip: ts.isoformat() for ip, ts in blacklist_global.items()}, f)

# -------------------------
# RUTES API
# -------------------------
@app.route("/report", methods=["POST"])
def report():
    """Rebre un informe d'una IP sospitosa"""
    token = request.headers.get("Authorization")
    if token != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    now = datetime.utcnow()
    blacklist_global[ip] = now
    save_blacklist()
    print(f"[{now}] Report received for IP: {ip}")
    return jsonify({"status": "ok"})

@app.route("/blacklist", methods=["GET"])
def get_blacklist():
    """Retorna la llista d'IPs a la blacklist"""
    token = request.headers.get("Authorization")
    if token != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401

    now = datetime.utcnow()
    # Eliminar IPs antigues
    expired_ips = [ip for ip, ts in blacklist_global.items()
                   if now - ts > timedelta(hours=BLACKLIST_TIMEOUT_HOURS)]
    for ip in expired_ips:
        del blacklist_global[ip]
    save_blacklist()

    return jsonify({"blacklist": list(blacklist_global.keys())})

# -------------------------
# INICI DEL SERVIDOR
# -------------------------
if __name__ == "__main__":
    # Render assigna el port via variable d'entorn PORT
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
