"""
main.py

Entry point for Windows Monitoring Agent.

Responsibilities:
- Collect system data (processes & services)
- Run detection modules
- Log activity & alerts
- Generate summary and reports
"""

from core.process_monitor import get_processes
from core.service_monitor import get_services
from core.detector import (
    detect_parent_child_anomalies,
    detect_suspicious_services,
    detect_unauthorized_processes
)
from core.logger import log_activity, log_alert

import os
import json
import time
from datetime import datetime


def generate_summary(all_alerts):
    """
    Generate summary of alerts based on severity levels.
    """
    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "TOTAL": len(all_alerts)
    }

    for alert in all_alerts:
        severity = alert.get("severity", "LOW")
        if severity in summary:
            summary[severity] += 1

    return summary


def save_report(summary, all_alerts, total_processes, total_services):
    """
    Save final report in JSON format with metadata and alerts.
    """
    os.makedirs("reports", exist_ok=True)

    # Filter high severity alerts
    high_alerts = [a for a in all_alerts if a.get("severity") == "HIGH"]

    report = {
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_processes": total_processes,
            "total_services": total_services
        },
        "summary": summary,
        "high_severity_alerts": high_alerts,
        "all_alerts": all_alerts
    }

    with open("reports/final_report.json", "w") as f:
        json.dump(report, f, indent=4)


def main():
    """
    Main execution loop for monitoring agent.
    Runs 3 scans with delay between each.
    """
    print("\n🔍 Starting Monitoring Agent...\n")

    for i in range(3):  # Run 3 scans
        print(f"\n================ SCAN {i+1} ================\n")

        # 🔹 Collect system data
        processes = get_processes()
        services = get_services()

        log_activity(f"Collected {len(processes)} processes")
        log_activity(f"Collected {len(services)} services")

        print(f"Total Processes: {len(processes)}")
        print(f"Total Services: {len(services)}")

        # 🔹 Run detection modules
        process_alerts = detect_parent_child_anomalies(processes)
        service_alerts = detect_suspicious_services(services)
        unauth_alerts = detect_unauthorized_processes(processes)

        all_alerts = process_alerts + service_alerts + unauth_alerts

        print("\n=== DETECTED ALERTS ===\n")

        # 🔹 Display alerts
        if not all_alerts:
            print("No suspicious activity ✅")
            log_activity("No suspicious activity detected")
        else:
            for alert in all_alerts[:10]:  # Show only first 10
                print(f"[{alert['severity']}] {alert['type']} → {alert.get('name', alert.get('service'))}")
                log_alert(f"{alert}", alert.get("severity", "INFO"))

            print(f"\nTotal Alerts: {len(all_alerts)}")
            log_activity(f"Total Alerts: {len(all_alerts)}")

        # 🔹 Generate summary
        summary = generate_summary(all_alerts)

        print("\n===== ALERT SUMMARY =====\n")
        print(f"HIGH: {summary['HIGH']}")
        print(f"MEDIUM: {summary['MEDIUM']}")
        print(f"LOW: {summary['LOW']}")
        print(f"\nTotal Alerts: {summary['TOTAL']}")

        log_activity(
            f"Summary - HIGH: {summary['HIGH']}, MEDIUM: {summary['MEDIUM']}, LOW: {summary['LOW']}, TOTAL: {summary['TOTAL']}"
        )

        # 🔹 Save report
        save_report(summary, all_alerts, len(processes), len(services))

        # 🔹 Delay before next scan
        if i < 2:
            print("\n⏳ Waiting 8 seconds before next scan...\n")
            time.sleep(8)

    print("\n✅ Monitoring completed (3 scans finished)\n")


if __name__ == "__main__":
    main()