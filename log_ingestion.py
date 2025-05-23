import boto3
import gzip
import json
import os
import sqlite3 as sql

# Configuration
BUCKET_NAME = 'cloudtrail-logs-mazen'
# Inside any script (whether in Website/ or SOC/)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # Gets SOC/
LOG_DB = os.path.join(BASE_DIR, 'cloudtrail_logs.db')
PROCESSED_LOGS_FILE = os.path.join(BASE_DIR, 'processed_files.txt')
LOCAL_LOG_DIR = 's3_logs'

# Setup Directory
os.makedirs(LOCAL_LOG_DIR, exist_ok=True)

# Load previously processed files
if os.path.exists(PROCESSED_LOGS_FILE):
    with open(PROCESSED_LOGS_FILE, 'r') as fh:
        processed = set(line.strip() for line in fh)
else:
    processed = set()

# Connect to AWS S3
s3 = boto3.client('s3')
paginator = s3.get_paginator('list_objects_v2')
pages = paginator.paginate(Bucket=BUCKET_NAME)

# Setup SQLite
conn = sql.connect(LOG_DB)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT,
    event_name TEXT,
    username TEXT,
    ip_address TEXT,
    region TEXT
)
""")

# Process new files
new_files = []

for page in pages:
    for obj in page.get('Contents', []):
        key = obj['Key']
        if not key.endswith('.json.gz') or key in processed:
            continue

        filename = os.path.join(LOCAL_LOG_DIR, os.path.basename(key))
        print(f"Downloading {key}")
        s3.download_file(BUCKET_NAME, key, filename)

        # Parse the file
        with gzip.open(filename, 'rt') as fh:
            data = json.load(fh)

        for record in data.get("Records", []):
            event_time = record.get("eventTime")
            event_name = record.get("eventName")
            user = record.get("userIdentity", {}).get("userName", "Unknown")
            ip = record.get("sourceIPAddress", "Unknown")
            region = record.get("awsRegion", "Unknown")

            cur.execute("""
                INSERT INTO logs (event_time, event_name, username, ip_address, region)
                VALUES (?, ?, ?, ?, ?)
            """, (event_time, event_name, user, ip, region))

        new_files.append(key)
        processed.add(key)

with open(PROCESSED_LOGS_FILE, 'w') as fh:
    for key in processed:
        fh.write(key + '\n')

conn.commit()
conn.close()

print(f"Ingested {len(new_files)} new log file(s) into SQLite")



