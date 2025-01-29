from flask import Flask, render_template
import os

app = Flask(__name__)

@app.route('/')
def view_logs():
    # Check if the log file exists
    if os.path.exists("intrusion_alerts.log"):
        with open("intrusion_alerts.log", "r") as file:
            logs = file.readlines()
        log_entries = [log.strip() for log in logs]
    else:
        log_entries = []

    return render_template("dashboard.html", logs=log_entries)

if __name__ == "__main__":
    app.run(debug=True, port=5000)

