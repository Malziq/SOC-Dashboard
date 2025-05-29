# SOC-Dashboard

This project is a cloud-based Security Operations Center (SOC) pipeline that ingests and analyzes AWS CloudTrail logs in real time to detect and alert on suspicious activity. It includes a backend ingestion system, a detection engine, and a Flask-based dashboard deployed on AWS EC2.

## Features

 Automated log ingestion from AWS S3 (CloudTrail)
- Real-time detection of:
  - Root account usage
  - Unauthorized access attempts
  - IAM policy changes
- Storage in a relational database (initially SQLite, prepared for Amazon RDS)
- Flask-based web dashboard for viewing alerts
- Periodic ingestion via cron job or AWS scheduling

## Tech Stack

- **Languages & Tools**: Python, SQL, Flask
- **AWS Services**: S3, CloudTrail, EC2, IAM, (RDS planned), (Lambda planned)
- **Libraries**: boto3, sqlite3


