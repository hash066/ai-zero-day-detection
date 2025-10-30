import win32evtlog
import json
import time
from kafka import KafkaProducer

# For production mode: live Sysmon streaming
server = None  # Local machine
log_type = 'Microsoft-Windows-Sysmon/Operational'

# Initialize Kafka Producer
producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

hand = win32evtlog.OpenEventLog(server, log_type)

seen = set()

print("🔄 Live Sysmon Producer started. Streaming new events to Kafka without duplicates...")

while True:
    try:
        events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_BACKWARDS_READ, 0)
        for event in events:
            if event.RecordNumber not in seen:
                data = {
                    "EventID": event.EventID,
                    "TimeGenerated": str(event.TimeGenerated),
                    "SourceName": event.SourceName,
                    "Message": event.StringInserts,
                }
                print("📤 Sending live event:", data)
                producer.send("sysmon-topic", json.dumps(data).encode("utf-8"))
                producer.flush()
                seen.add(event.RecordNumber)
    except Exception as e:
        print(f"Error reading event log: {e}. Reopening log...")
        hand = win32evtlog.OpenEventLog(server, log_type)
    time.sleep(1)
