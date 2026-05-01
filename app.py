from flask import Flask, request, render_template, jsonify
from datetime import datetime, timedelta

app = Flask(__name__)

attempts = {}
blocked_ips = {}
logs = []

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
    ip = request.remote_addr or "unknown"

    if ip in blocked_ips:
        if datetime.now() < blocked_ips[ip]:
            return "🚫 BLOCKED: Suspicious activity detected!"
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

            if len(attempts[ip]) > MAX_ATTEMPTS:
                blocked_ips[ip] = now + timedelta(seconds=BLOCK_TIME)
                message = "🚫 BLOCKED: Too many attempts!"
            else:
                message = f"❌ Failed Attempt {len(attempts[ip])}"

        logs.append({
            "ip": ip,
            "time": now.strftime("%H:%M:%S"),
            "status": status,
            "location": get_location(ip)
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
        "success": success,
        "fail": fail
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)