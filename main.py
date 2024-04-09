import pandas as pd
from scapy.all import *
from ipaddress import ip_address
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder
import joblib
import time
from elasticsearch import Elasticsearch

# Load the trained model
model = joblib.load('ransomware_rf.sav')

# Initialize DataFrame to store packet features and predictions
data = pd.DataFrame(columns=['packet_length', 'protocol_type', 'src_ip', 'dst_ip',
                              'src_port', 'dst_port', 'flags', 'time_stamp', 'payload_size', 'prediction'])

# Initialize Elasticsearch client
try:
    es = Elasticsearch("http://192.168.196.98:9200")
except Exception as e:
    raise Exception(e)

# Function to extract features from a single packet
def extract_features(packet):
    if IP in packet:
        packet_length = len(packet)
        protocol_type = packet[IP].proto
        src_ip = int(ip_address(packet[IP].src))  # Convert source IP to integer
        dst_ip = int(ip_address(packet[IP].dst))  # Convert destination IP to integer
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flags = None
        else:
            src_port = None
            dst_port = None
            flags = None
        time_stamp = packet.time
        payload_size = len(packet.payload)

        return {
            'packet_length': packet_length,
            'protocol_type': protocol_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'flags': flags,
            'time_stamp': time_stamp,
            'payload_size': payload_size
        }
    else:
        return None

# Function to convert timestamp to seconds
def convert_timestamp_to_seconds(timestamp):
    return int(timestamp)

# Function to apply model on features
def apply_model(features):
    df = pd.DataFrame([features])

    # Convert timestamp to seconds
    df['time_stamp'] = df['time_stamp'].apply(convert_timestamp_to_seconds)

    # Label encode the "flags" column
    le = LabelEncoder()
    df['flags'] = le.fit_transform(df['flags'].astype(str))

    # Impute missing values
    imputer = SimpleImputer(strategy='mean')
    X = imputer.fit_transform(df)

    # Apply model
    prediction = model.predict(X)[0]

    return prediction

# Packet processing callback
def packet_callback(packet):
    features = extract_features(packet)
    if features:
        prediction = apply_model(features)
        features['prediction'] = prediction
        data.loc[len(data)] = features

        # Index into Elasticsearch only if prediction indicates an attack
        if prediction == 'attack':
            try:
                es.index(index="ransomware-alerts", body=features)
                print("Ransomware alert send to elasticsearch:",features)
            except Exception as e:
                print("Failed to index to Elasticsearch:", e)

        # Periodically write to CSV file
        if len(data) % 100 == 0:
            data.to_csv('predictions.csv', index=False)

# Start capturing live traffic indefinitely
try:
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("Packet capture stopped by user.")
finally:
    # Write remaining data to CSV file
    data.to_csv('predictions.csv', index=False)

