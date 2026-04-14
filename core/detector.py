"""
detector.py

This module contains detection logic for:
- Suspicious parent-child processes
- Suspicious services
- Unauthorized / suspicious processes

It uses rule-based and behavioral detection techniques.
"""

from core.utils import load_json
import re

# Load detection rules safely
try:
    rules = load_json("config/rules.json")
except Exception:
    rules = {
        "parent_child": [],
        "suspicious_paths": []
    }


def load_whitelist():
    """
    Load whitelist of trusted process/service names.
    Returns list in lowercase for easy comparison.
    """
    try:
        whitelist = load_json("config/whitelist.json")
    except Exception:
        whitelist = []
    return [w.lower() for w in whitelist]


def remove_duplicates(alerts):
    """
    Remove duplicate alerts based on key attributes.
    """
    seen = set()
    unique_alerts = []

    for alert in alerts:
        key = (
            alert.get("type"),
            alert.get("name"),
            alert.get("pid"),
            alert.get("service")
        )

        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    return unique_alerts


def is_suspicious_name(name):
    """
    Detect suspicious process names based on pattern:
    - Contains both letters and numbers
    - Short random-like names (common in malware)
    """
    name = name.lower()

    if re.search(r'[a-z]', name) and re.search(r'[0-9]', name):
        if len(name) <= 12:
            return True

    return False


def detect_parent_child_anomalies(processes):
    """
    Detect suspicious parent-child process relationships.
    """
    alerts = []

    for pid, proc in processes.items():
        parent_pid = proc["ppid"]

        if parent_pid in processes:
            parent = processes[parent_pid]

            parent_name = parent["name"].lower()
            child_name = proc["name"].lower()

            # Rule-based detection
            for rule in rules.get("parent_child", []):
                if parent_name == rule["parent"] and child_name == rule["child"]:
                    alerts.append({
                        "type": "Suspicious Parent-Child",
                        "parent": parent_name,
                        "child": child_name,
                        "pid": pid,
                        "severity": rule.get("severity", "MEDIUM")
                    })

            # Behavioral detection
            if parent_name in ["winword.exe", "excel.exe"] and child_name in ["cmd.exe", "powershell.exe"]:
                alerts.append({
                    "type": "Office spawning shell",
                    "parent": parent_name,
                    "child": child_name,
                    "pid": pid,
                    "severity": "HIGH"
                })

            if parent_name == "chrome.exe" and child_name in ["cmd.exe", "powershell.exe"]:
                alerts.append({
                    "type": "Browser spawning shell",
                    "parent": parent_name,
                    "child": child_name,
                    "pid": pid,
                    "severity": "HIGH"
                })

    return remove_duplicates(alerts)


def detect_suspicious_services(services):
    """
    Detect services running from suspicious paths.
    """
    alerts = []
    whitelist_lower = load_whitelist()

    for service in services:
        path = service.get("path", "") or ""
        service_name = service.get("name", "").lower()

        for rule in rules.get("suspicious_paths", []):
            if (
                rule["keyword"].lower() in path.lower()
                and service_name not in whitelist_lower
            ):
                alerts.append({
                    "type": "Suspicious Service Path",
                    "service": service.get("name"),
                    "path": path,
                    "severity": rule.get("severity", "MEDIUM")
                })

    return remove_duplicates(alerts)


def detect_unauthorized_processes(processes):
    """
    Detect suspicious processes based on:
    - Execution path
    - Suspicious directories
    - Naming patterns
    """
    alerts = []
    whitelist_lower = load_whitelist()

    suspicious_dirs = [
        "\\AppData\\Local\\Temp",
        "\\AppData\\Roaming",
        "\\Temp",
        "\\Downloads"
    ]

    for pid, proc in processes.items():
        name = proc.get("name", "unknown")
        path = proc.get("path", "")

        name_lower = name.lower()
        path_lower = path.lower()

        # Rule-based suspicious path
        for rule in rules.get("suspicious_paths", []):
            if (
                rule["keyword"].lower() in path_lower
                and name_lower not in whitelist_lower
            ):
                alerts.append({
                    "type": "Suspicious Process",
                    "name": name,
                    "path": path,
                    "pid": pid,
                    "severity": rule.get("severity", "MEDIUM")
                })

        # Suspicious directory execution
        for dir_keyword in suspicious_dirs:
            if dir_keyword.lower() in path_lower and name_lower not in whitelist_lower:
                alerts.append({
                    "type": "Suspicious Directory Execution",
                    "name": name,
                    "path": path,
                    "pid": pid,
                    "severity": "HIGH"
                })

        # Suspicious naming pattern (combined with path condition)
        if (
            is_suspicious_name(name_lower)
            and name_lower not in whitelist_lower
            and ("temp" in path_lower or "appdata" in path_lower)
        ):
            alerts.append({
                "type": "Suspicious Process Name",
                "name": name,
                "pid": pid,
                "severity": "MEDIUM"
            })

    return remove_duplicates(alerts)