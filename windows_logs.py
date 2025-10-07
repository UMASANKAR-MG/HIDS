import win32evtlog
import datetime
import ctypes
import sys

def collect_and_save_event_logs(log_types=["System", "Application", "Security"], event_ids=None, event_count=None):

    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("This script requires administrator privileges. Please restart the script as administrator.")
            sys.exit()
    except:
        print("Error checking admin status.")
        sys.exit()

    # Prompt user for start time
    start_time = None
    while start_time is None:
        date_input = input("Enter the start date (YYYY-MM-DD): ")
        time_input = input("Enter the start time (HH:MM): ")
        try:
            start_time = datetime.datetime.strptime(f"{date_input} {time_input}", "%Y-%m-%d %H:%M")
        except ValueError:
            print("Invalid date or time format. Please try again.")
            start_time = None

    events = {log_type: [] for log_type in log_types}

    for log_type in log_types:
        server = 'localhost'
        log_handle = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        try:
            while True:
                logs = win32evtlog.ReadEventLog(log_handle, flags, 0)
                if not logs:
                    break
                for event in logs:
                    # Apply filters
                    if start_time and event.TimeGenerated < start_time:
                        continue
                    if event_ids and event.EventID not in event_ids:
                        continue

                    record = {
                        "EventID": event.EventID,
                        "EventCategory": event.EventCategory,
                        "TimeGenerated": event.TimeGenerated.Format(),
                        "SourceName": event.SourceName,
                        "EventType": event.EventType,
                        "EventData": event.StringInserts,
                    }
                    events[log_type].append(record)

                    if event_count and len(events[log_type]) >= event_count:
                        break
                if event_count and len(events[log_type]) >= event_count:
                    break
        except Exception as e:
            print(f"An error occurred while reading {log_type} logs: {e}")
        finally:
            win32evtlog.CloseEventLog(log_handle)

        filename = f"{log_type.lower()}_event_logs.txt"
        with open(filename, "w") as f:
            for event in events[log_type]:
                f.write(f"Event ID: {event['EventID']}\n")
                f.write(f"Category: {event['EventCategory']}\n")
                f.write(f"Generated Time: {event['TimeGenerated']}\n")
                f.write(f"Source: {event['SourceName']}\n")
                f.write(f"Type: {event['EventType']}\n")
                f.write(f"Data: {event['EventData']}\n")
                f.write("\n" + "="*40 + "\n\n")
        print(f"Logs saved to {filename}")

