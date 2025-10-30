from kafka import KafkaConsumer
import json, os, sys
# Add the parent directory to sys.path so that 'online_files' can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from online_files.Feature_extraction import extract_features  # connects directly!

DATA_OUT = "data/processed/streamed_features.json"

consumer = KafkaConsumer(
    'sysmon-topic',
    bootstrap_servers='localhost:9092',
    auto_offset_reset='earliest',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

print("✅ Consumer started. Listening for Sysmon logs...")

for msg in consumer:
    log = msg.value
    print("📥 Received:", log)
    
    features = extract_features(log)  # runs your logic!
    print("🧠 Extracted features:", features)

    # append features into processed dataset
    os.makedirs(os.path.dirname(DATA_OUT), exist_ok=True)
    with open(DATA_OUT, "a") as f:
        f.write(json.dumps(features) + "\n")
