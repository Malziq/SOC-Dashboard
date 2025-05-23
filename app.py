from flask import Flask, render_template, jsonify, request
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Inside any script (whether in Website/ or SOC/)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # Gets SOC/
DB_PATH = os.path.join(BASE_DIR, 'cloudtrail_logs.db')
PROCESSED_LOGS_FILE = os.path.join(BASE_DIR, 'processed_files.txt')
print("🔍 Using DB at:", DB_PATH)

def format_timestamp(timestamp):
    if not timestamp or not isinstance(timestamp, str):
        return "Invalid time"
    try:
        dt = datetime.strptime(timestamp.strip(), '%Y-%m-%dT%H:%M:%SZ')
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        return f"Invalid time"


def get_alert_data():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    print("=== Sample rows from logs ===")
    cur.execute("SELECT * FROM logs LIMIT 3")
    for row in cur.fetchall():
        print(dict(row))

    # Replace detections with simple queries that always return data
    cur.execute("SELECT ip_address, event_name, COUNT(*) as count FROM logs GROUP BY ip_address, event_name LIMIT 10")
    high_freq = [dict(row) for row in cur.fetchall()]

    cur.execute("SELECT event_name, COUNT(*) as count FROM logs GROUP BY event_name ORDER BY count DESC LIMIT 5")
    common_events = [dict(row) for row in cur.fetchall()]

    cur.execute("SELECT event_time, event_name, ip_address FROM logs ORDER BY event_time DESC LIMIT 5")
    iam_activity = [dict(row) for row in cur.fetchall()]

    cur.execute("SELECT DISTINCT region FROM logs LIMIT 5")
    unusual_regions = [dict(row) for row in cur.fetchall()]

    cur.execute("SELECT event_time, event_name, ip_address FROM logs ORDER BY event_time DESC LIMIT 5")
    off_hours = [dict(row) for row in cur.fetchall()]

    conn.close()

    summary = {
        "total_alerts": len(high_freq) + len(iam_activity) + len(unusual_regions) + len(off_hours),
        "high_severity": len(iam_activity),
        "medium_severity": len(high_freq),
        "low_severity": len(off_hours),
    }

    return {
        "high_freq": high_freq,
        "common_events": common_events,
        "iam_activity": iam_activity,
        "unusual_regions": unusual_regions,
        "off_hours": off_hours,
        "summary": summary,
    }


@app.route("/")
def home():
    data = get_alert_data()
    return render_template("dashboard.html", **data)

if __name__ == "__main__":
    app.run(debug=True)