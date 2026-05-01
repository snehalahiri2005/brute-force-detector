from flask import Flask, request, render_template
from datetime import datetime, timedelta

app = Flask(__name__)

attempts = {}
blocked_ips = {}

MAX_ATTEMPTS = 5
BLOCK_TIME = 60  # seconds

@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    ip = request.remote_addr

    if ip in blocked_ips:
        if datetime.now() < blocked_ips[ip]:
            return f"❌ You are blocked! Try later."
        else:
            del blocked_ips[ip]

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        now = datetime.now()

        if ip not in attempts:
            attempts[ip] = []

        attempts[ip].append(now)

        # Keep only last 1 min attempts
        attempts[ip] = [t for t in attempts[ip] if now - t < timedelta(seconds=60)]

        if len(attempts[ip]) > MAX_ATTEMPTS:
            blocked_ips[ip] = now + timedelta(seconds=BLOCK_TIME)
            message = "🚫 Too many attempts! You are blocked."
        else:
            message = f"⚠️ Failed login attempt {len(attempts[ip])}"

    return render_template("index.html", message=message)

@app.route("/logs")
def logs():
    return {
        "attempts": {ip: len(times) for ip, times in attempts.items()},
        "blocked_ips": list(blocked_ips.keys())
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)