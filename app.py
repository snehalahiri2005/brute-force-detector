from flask import Flask, request, render_template, jsonify, send_file
from datetime import datetime, timedelta
import csv, io, json, os

app = Flask(__name__)

attempts = {}
blocked_ips = {}
blocked_users = {}
logs = []
timeline = []

VALID_USERS = {"admin": "1234", "user": "1234"}
API_KEY = "soc-secret-key"

# --- CONFIG ---
BASE_BLOCK = 30

# --- HELPERS ---
def get_location(ip):
    locations = ["India","USA","Germany","UK"]
    return locations[hash(ip)%len(locations)]

def save_logs():
    with open("logs.json","w") as f:
        json.dump(logs,f)

# --- ROUTES ---
@app.route("/", methods=["GET","POST"])
def login():
    message=""
    ip=request.form.get("ip") or request.remote_addr or "127.0.0.1"

    # unblock expired
    if ip in blocked_ips and datetime.now() > blocked_ips[ip]:
        del blocked_ips[ip]
        attempts[ip] = []

    if request.method=="POST":
        username=request.form["username"]
        password=request.form["password"]
        now=datetime.now()

        status="FAILED"
        threat="NONE"
        action="NONE"

        # block check
        if ip in blocked_ips:
            remaining=int((blocked_ips[ip]-now).total_seconds())
            return f"IP blocked ({remaining}s)"

        # success
        if username in VALID_USERS and VALID_USERS[username]==password:
            status="SUCCESS"
            message="Login success"
            attempts[ip]=[]
        else:
            attempts.setdefault(ip,[]).append(now)
            attempts[ip]=[t for t in attempts[ip] if now-t<timedelta(seconds=60)]
            count=len(attempts[ip])

            # threat scoring
            score = count * 10

            if score < 30:
                threat,action="LOW","LOG"
            elif score < 60:
                threat,action="MEDIUM","WARN"
            elif score < 90:
                threat,action="HIGH","BLOCK IP"
                blocked_ips[ip]=now+timedelta(seconds=count*5)
            else:
                threat,action="CRITICAL","BLOCK USER"
                blocked_users[username]=now+timedelta(seconds=120)

            message=f"Attempt {count} | {threat}"

        # behavior detection
        users_from_ip = set([l["user"] for l in logs if l["ip"]==ip])
        if len(users_from_ip) > 3:
            attack_type="Credential Stuffing"
        elif count > 5:
            attack_type="Brute Force"
        else:
            attack_type="Normal"

        logs.append({
            "ip":ip,
            "user":username,
            "time":now.strftime("%H:%M:%S"),
            "status":status,
            "threat":threat,
            "action":action,
            "type":attack_type,
            "location":get_location(ip)
        })

        timeline.append({"time":now.strftime("%H:%M:%S"),"count":count})

        save_logs()

    return render_template("index.html", message=message)


@app.route("/logs")
def get_logs():
    if request.headers.get("x-api-key")!=API_KEY:
        return jsonify({"error":"unauthorized"}),403

    success=sum(1 for l in logs if l["status"]=="SUCCESS")
    fail=sum(1 for l in logs if l["status"]=="FAILED")

    top_ip=max(attempts,key=lambda x:len(attempts[x])) if attempts else "-"

    return jsonify({
        "logs":logs[-20:],
        "timeline":timeline[-20:],
        "blocked_ips":list(blocked_ips.keys()),
        "success":success,
        "fail":fail,
        "top_ip":top_ip
    })


@app.route("/reset")
def reset():
    attempts.clear()
    logs.clear()
    timeline.clear()
    return "reset done"


@app.route("/export")
def export():
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
    app.run(debug=True)