from flask import Flask, request, render_template, jsonify, send_file
from datetime import datetime, timedelta
import csv, io

app = Flask(__name__)

attempts = {}
blocked_ips = {}
blocked_users = {}
logs = []
timeline = []

VALID_USERS = {
    "admin": {"password": "1234", "role": "admin"},
    "user": {"password": "1234", "role": "user"}
}

API_KEY = "soc-secret-key"
BLOCK_TIME = 60

def get_location(ip):
    locations = ["India", "USA", "Germany", "UK"]
    return locations[hash(ip) % len(locations)]

@app.route("/", methods=["GET","POST"])
def login():
    message=""
    ip=request.remote_addr or "127.0.0.1"

    if ip in blocked_ips and datetime.now() < blocked_ips[ip]:
        return "🚫 IP BLOCKED"

    if request.method=="POST":
        username=request.form["username"]
        password=request.form["password"]
        now=datetime.now()
        status="FAILED"

        if username in blocked_users and datetime.now() < blocked_users[username]:
            return "🚫 USER BLOCKED"

        if username in VALID_USERS and VALID_USERS[username]["password"]==password:
            status="SUCCESS"
            message="✅ Login successful"
        else:
            if ip not in attempts:
                attempts[ip]=[]

            attempts[ip].append(now)
            attempts[ip]=[t for t in attempts[ip] if now-t<timedelta(seconds=60)]

            count=len(attempts[ip])

            if count<=3:
                threat,action="LOW","LOGGED"
            elif count<=5:
                threat,action="MEDIUM","WARNING"
            elif count<=8:
                threat,action="HIGH","IP BLOCKED"
                blocked_ips[ip]=now+timedelta(seconds=BLOCK_TIME)
            else:
                threat,action="CRITICAL","USER BLOCKED"
                blocked_users[username]=now+timedelta(seconds=300)

            message=f"❌ Attempt {count} | {threat}"

        attack_type = "Brute Force" if count>6 else ("Password Spray" if count>3 else "Normal")

        logs.append({
            "ip":ip,
            "user":username,
            "time":now.strftime("%H:%M:%S"),
            "status":status,
            "location":get_location(ip),
            "type":attack_type,
            "threat":threat if status=="FAILED" else "NONE",
            "action":action if status=="FAILED" else "LOGIN SUCCESS"
        })

        timeline.append({"time":now.strftime("%H:%M:%S"),"count":count})

    return render_template("index.html", message=message)


@app.route("/logs")
def get_logs():
    if request.headers.get("x-api-key")!=API_KEY:
        return jsonify({"error":"Unauthorized"}),403

    success=sum(1 for l in logs if l["status"]=="SUCCESS")
    fail=sum(1 for l in logs if l["status"]=="FAILED")

    return jsonify({
        "logs":logs[-20:],
        "timeline":timeline[-20:],
        "blocked_ips":list(blocked_ips.keys()),
        "blocked_users":list(blocked_users.keys()),
        "success":success,
        "fail":fail
    })

@app.route("/unblock_ip/<ip>")
def unblock_ip(ip):
    blocked_ips.pop(ip,None)
    return "OK"

@app.route("/unblock_user/<user>")
def unblock_user(user):
    blocked_users.pop(user,None)
    return "OK"

@app.route("/export_logs")
def export_logs():
    output=io.StringIO()
    writer=csv.DictWriter(output,fieldnames=logs[0].keys())
    writer.writeheader()
    writer.writerows(logs)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="logs.csv"
    )

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)