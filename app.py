from flask import Flask, request, render_template, jsonify
from datetime import datetime, timedelta

app = Flask(__name__)

attempts = {}
blocked_ips = {}
logs = []
timeline = []

VALID_USER = "admin"
VALID_PASS = "1234"

MAX_ATTEMPTS = 5
BLOCK_TIME = 60

def get_location(ip):
    locations = ["India", "USA", "Germany", "UK"]
    return locations[hash(ip) % len(locations)]

@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    ip = request.remote_addr or "127.0.0.1"

    # Block check
    if ip in blocked_ips:
        if datetime.now() < blocked_ips[ip]:
            return "🚫 BLOCKED: Suspicious activity!"
        else:
            del blocked_ips[ip]

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        now = datetime.now()
        status = "FAILED"

        if username == VALID_USER and password == VALID_PASS:
            status = "SUCCESS"
            message = "✅ Login successful"
        else:
            if ip not in attempts:
                attempts[ip] = []

            attempts[ip].append(now)
            attempts[ip] = [t for t in attempts[ip] if now - t < timedelta(seconds=60)]

            count = len(attempts[ip])

            # 🔥 Threat Detection + Response Engine
            if count <= 3:
                threat = "LOW"
                action = "LOGGED"

            elif count <= 5:
                threat = "MEDIUM"
                action = "WARNING"

            elif count <= 8:
                threat = "HIGH"
                blocked_ips[ip] = now + timedelta(seconds=BLOCK_TIME)
                action = "IP BLOCKED"

            else:
                threat = "CRITICAL"
                blocked_ips[ip] = now + timedelta(seconds=300)
                action = "PERMANENT BLOCK"

            message = f"❌ Attempt {count} | {threat}"

        # Attack Type
        count = len(attempts.get(ip, []))
        if count > 6:
            attack_type = "Brute Force"
        elif count > 3:
            attack_type = "Password Spray"
        else:
            attack_type = "Normal"

        # Logs
        logs.append({
            "ip": ip,
            "time": now.strftime("%H:%M:%S"),
            "status": status,
            "location": get_location(ip),
            "type": attack_type,
            "threat": threat if status == "FAILED" else "NONE",
            "action": action if status == "FAILED" else "LOGIN SUCCESS"
        })

        # Timeline (for graph)
        timeline.append({
            "time": now.strftime("%H:%M:%S"),
            "count": len(attempts.get(ip, []))
        })

    return render_template("index.html", message=message)

@app.route("/logs")
def get_logs():
    success = sum(1 for l in logs if l["status"] == "SUCCESS")
    fail = sum(1 for l in logs if l["status"] == "FAILED")

    return jsonify({
        "attempts": {ip: len(times) for ip, times in attempts.items()},
        "blocked": list(blocked_ips.keys()),
        "logs": logs[-10:],
        "timeline": timeline[-10:],
        "success": success,
        "fail": fail
    })

@app.route("/unblock/<ip>")
def unblock(ip):
    if ip in blocked_ips:
        del blocked_ips[ip]
    return "Unblocked"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)