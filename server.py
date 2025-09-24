import json
import os
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# Fitxers de configuració i dades
POLICY_FILE = "policy.json"
LOG_FILE = "logs.json"
STATE_FILE = "state.json"

# Càrrega de polítiques
with open(POLICY_FILE, "r", encoding="utf-8") as f:
    POLICY = json.load(f)

# Inicialització de fitxers si no existeixen
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)

if not os.path.exists(STATE_FILE):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"blocked_servers": []}, f)


def log_event(action, details):
    """Afegeix un event al fitxer de logs"""
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        logs = json.load(f)

    logs.append({
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "details": details
    })

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)


def load_state():
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


@app.route("/")
def index():
    return jsonify({
        "message": "ArCom Central API",
        "endpoints": ["/logs", "/block", "/status"]
    })


@app.route("/logs")
def get_logs():
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        logs = json.load(f)
    return jsonify(logs)


@app.route("/status")
def status():
    state = load_state()
    return jsonify(state)


@app.route("/block", methods=["POST"])
def block_server():
    """
    Endpoint per bloquejar un servidor ofensiu.
    JSON input esperat:
    {
      "server_id": "srv123",
      "requested_by": "admin",
      "reason": "NSFW"
    }
    """
    data = request.json
    server_id = data.get("server_id")
    user_role = data.get("requested_by")
    reason = data.get("reason", "No reason provided")

    if not server_id or not user_role:
        return jsonify({"error": "Falten camps obligatoris"}), 400

    # Verificar si l'usuari té permís
    role_policy = POLICY["roles"].get(user_role)
    if not role_policy or not role_policy.get("can_request_disable", False):
        return jsonify({"error": "No tens permisos per fer això"}), 403

    # Carregar estat
    state = load_state()
    if server_id in state["blocked_servers"]:
        return jsonify({"message": "El servidor ja està bloquejat"}), 200

    # Bloquejar
    state["blocked_servers"].append(server_id)
    save_state(state)

    log_event("BLOCK_SERVER", {
        "server_id": server_id,
        "requested_by": user_role,
        "reason": reason
    })

    return jsonify({
        "message": f"Servidor {server_id} bloquejat correctament",
        "reason": reason
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
