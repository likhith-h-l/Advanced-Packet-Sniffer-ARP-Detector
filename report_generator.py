"""
Report Generator Module.

Provides utilities to dynamically generate CSV reports from captured packets
and security alerts. Ensures that data is properly mapped to standardized columns.
"""
import os
import csv
from datetime import datetime
from typing import List, Dict, Any, Optional

# Base directory for reports – sits alongside this module
BASE_REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")

# Ensure the reports folder exists at import time
try:
    os.makedirs(BASE_REPORT_DIR, exist_ok=True)
except Exception as e:
    # If we cannot create the folder we fall back to cwd and continue – the function will still try to write.
    print(f"[REPORT] Unable to create reports directory '{BASE_REPORT_DIR}': {e}")
    BASE_REPORT_DIR = os.getcwd()


def _default(value: Any, fallback: str = "N/A") -> str:
    """
    Utility to return a safe default when a value is missing or None.
    This keeps the CSV rows well-formed without raising KeyError/TypeError.
    """
    return str(value) if value is not None else fallback


def generate_csv_report(packets: List[Dict[str, Any]]) -> str:
    """
    Generate a CSV report from a list of packet dictionaries.

    The function creates (or overwrites) a timestamped CSV file in the
    ``reports`` directory and returns the absolute path of the created file.
    
    Args:
        packets (List[Dict[str, Any]]): List of packet dictionaries to export.
        
    Returns:
        str: Absolute path to the generated CSV file.
    """
    if not isinstance(packets, list):
        raise TypeError("packets must be a list of packet dictionaries")

    # Build a filename like "report_20230622_115800.csv"
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(BASE_REPORT_DIR, f"report_{timestamp_str}.csv")

    header = ["Timestamp", "Source IP", "Destination IP", "Protocol", "Packet Length"]

    try:
        with open(report_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header)
            for pkt in packets:
                # Use safe getters – the packet dict may not contain all keys
                row = [
                    _default(pkt.get("timestamp")),
                    _default(pkt.get("source_ip")),
                    _default(pkt.get("destination_ip")),
                    _default(pkt.get("protocol")),
                    _default(pkt.get("length")),
                ]
                writer.writerow(row)
    except PermissionError as exc:
        print(f"[REPORT] Permission denied writing CSV report. Is the file open? Error: {exc}")
        raise
    except Exception as exc:
        # Any I/O problem should not crash the app – propagate a friendly message.
        print(f"[REPORT] Failed to write CSV report: {exc}")
        raise

    return report_path


def generate_alerts_report(alerts: List[Dict[str, Any]]) -> str:
    """
    Generate a CSV report from a list of alert dictionaries.
    
    Args:
        alerts (List[Dict[str, Any]]): List of alert dictionaries to export.
        
    Returns:
        str: Absolute path to the generated alerts CSV file.
    """
    if not isinstance(alerts, list):
        raise TypeError("alerts must be a list of alert dictionaries")

    report_path = os.path.join(BASE_REPORT_DIR, "alerts.csv")
    header = ["Timestamp", "Severity", "Alert Type", "Description"]

    try:
        with open(report_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header)
            for alert in alerts:
                row = [
                    _default(alert.get("timestamp")),
                    _default(alert.get("severity", "INFO")),
                    _default(alert.get("type")),
                    _default(alert.get("message")),
                ]
                writer.writerow(row)
    except PermissionError as exc:
        print(f"[REPORT] Permission denied writing alerts CSV report. Is the file open? Error: {exc}")
        raise
    except Exception as exc:
       
        raise

    return report_path
