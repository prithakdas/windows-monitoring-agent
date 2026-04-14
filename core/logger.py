import os
from datetime import datetime

LOG_DIR = "logs"
ALERT_LOG = os.path.join(LOG_DIR, "alerts.log")
ACTIVITY_LOG = os.path.join(LOG_DIR, "activity.log")

# Ensure log folder exists
os.makedirs(LOG_DIR, exist_ok=True)


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_activity(message):
    try:
        timestamp = get_timestamp()
        with open(ACTIVITY_LOG, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
            f.flush()
    except Exception as e:
        print(f"[LOG ERROR] Activity log failed: {e}")


def log_alert(message, severity="INFO"):
    try:
        timestamp = get_timestamp()
        log_entry = f"[{timestamp}] [{severity}] ALERT: {message}\n"

        with open(ALERT_LOG, "a") as f:
            f.write(log_entry)
            f.flush()

    except Exception as e:
        print(f"[LOG ERROR] Alert log failed: {e}")