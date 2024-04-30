import os
import time
import pandas as pd
from scapy.all import *
from ipaddress import ip_address
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import LabelEncoder
import joblib
from statistics import median, stdev, variance

# Load the trained model
rf_classifier = joblib.load('ransomware_rf2.sav')

def extract_features_from_session(session_packets):
    session_length = len(session_packets)
    total_packet_length = sum(len(pkt) for pkt in session_packets)
    total_payload_size = sum(len(pkt.payload) for pkt in session_packets)
    start_time = session_packets[0].time
    end_time = session_packets[-1].time
    
    # Initialize default values for features
    protocol_type = None
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    flags = None
    
    # IPv4 features
    version_ipv4 = None
    ihl_ipv4 = None
    type_of_service_ipv4 = None
    total_length_ipv4 = None
    identification_ipv4 = None
    fragment_offset_ipv4 = None
    ttl_ipv4 = None
    header_checksum_ipv4 = None
    options_ipv4 = None
    
    # IPv6 features
    version_ipv6 = None
    traffic_class_ipv6 = None
    flow_label_ipv6 = None
    payload_length_ipv6 = None
    next_header_ipv6 = None
    hop_limit_ipv6 = None
    
    # Payload-level features
    payload_lengths = [len(pkt.payload) for pkt in session_packets]
    mean_payload_length = sum(payload_lengths) / len(payload_lengths)
    median_payload_length = median(payload_lengths)
    max_payload_length = max(payload_lengths)
    min_payload_length = min(payload_lengths)
    std_payload_length = stdev(payload_lengths) if len(payload_lengths) > 1 else 0  # Avoid division by zero
    var_payload_length = variance(payload_lengths) if len(payload_lengths) > 1 else 0  # Avoid division by zero
    
    # Extract features from the packet in the session
    first_pkt = session_packets[0]
    if IP in first_pkt:
        protocol_type = first_pkt[IP].proto
        src_ip = int(ip_address(first_pkt[IP].src))
        dst_ip = int(ip_address(first_pkt[IP].dst))
        
        # Extract IPv4 header features
        version_ipv4 = first_pkt[IP].version
        ihl_ipv4 = first_pkt[IP].ihl
        type_of_service_ipv4 = first_pkt[IP].tos
        total_length_ipv4 = first_pkt[IP].len
        identification_ipv4 = first_pkt[IP].id
        fragment_offset_ipv4 = first_pkt[IP].frag
        ttl_ipv4 = first_pkt[IP].ttl
        header_checksum_ipv4 = first_pkt[IP].chksum
        options_ipv4 = first_pkt[IP].options if first_pkt[IP].options else None
    
    if IPv6 in first_pkt:
        protocol_type = 6  # IPv6 protocol type
        src_ip = first_pkt[IPv6].src
        dst_ip = first_pkt[IPv6].dst
        
        # Extract IPv6 header features
        version_ipv6 = first_pkt[IPv6].version
        traffic_class_ipv6 = first_pkt[IPv6].tc
        flow_label_ipv6 = first_pkt[IPv6].fl
        payload_length_ipv6 = first_pkt[IPv6].plen
        next_header_ipv6 = first_pkt[IPv6].nh
        hop_limit_ipv6 = first_pkt[IPv6].hlim
    else:
        # If IPv6 features are missing, assign default values
        version_ipv6 = 0
        traffic_class_ipv6 = 0
        flow_label_ipv6 = 0
        payload_length_ipv6 = 0
        next_header_ipv6 = None
        hop_limit_ipv6 = None
    
    if TCP in first_pkt:
        src_port = first_pkt[TCP].sport
        dst_port = first_pkt[TCP].dport
        flags = first_pkt[TCP].flags
    elif UDP in first_pkt:
        src_port = first_pkt[UDP].sport
        dst_port = first_pkt[UDP].dport
    
    # Create a dictionary of features
    features = {
        'session_length': session_length,
        'total_packet_length': total_packet_length,
        'total_payload_size': total_payload_size,
        'start_time': start_time,
        'end_time': end_time,
        'protocol_type': protocol_type,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'flags': flags,
        # IPv4 features
        'version_ipv4': version_ipv4,
        'ihl_ipv4': ihl_ipv4,
        'type_of_service_ipv4': type_of_service_ipv4,
        'total_length_ipv4': total_length_ipv4,
        'identification_ipv4': identification_ipv4,
        'fragment_offset_ipv4': fragment_offset_ipv4,
        'ttl_ipv4': ttl_ipv4,
        'header_checksum_ipv4': header_checksum_ipv4,
        'options_ipv4': options_ipv4,
        # IPv6 features
        'version_ipv6': version_ipv6,
        'traffic_class_ipv6': traffic_class_ipv6,
        'flow_label_ipv6': flow_label_ipv6,
        'payload_length_ipv6': payload_length_ipv6,
        'next_header_ipv6': next_header_ipv6,
        'hop_limit_ipv6': hop_limit_ipv6,
        # Payload-level features
        'mean_payload_length': mean_payload_length,
        'median_payload_length': median_payload_length,
        'max_payload_length': max_payload_length,
        'min_payload_length': min_payload_length,
        'std_payload_length': std_payload_length,
        'var_payload_length': var_payload_length
    }
    
    return features

def extract_features_from_live_traffic_and_save(duration=120, capture_file='traffic.cap'):
    packets = sniff(timeout=duration)  # Sniff packets for the specified duration
    wrpcap(capture_file, packets)  # Write captured packets to the capture file
    sessions = packets.sessions()
    all_features = []
    for session_key in sessions:
        session_packets = sessions[session_key]
        features = extract_features_from_session(session_packets)
        all_features.append(features)
    return all_features

def make_predictions_and_save():
    features = extract_features_from_live_traffic_and_save()
    
    # Create DataFrame with all expected features
    df = pd.DataFrame(features, columns=[
        'session_length', 'total_packet_length', 'total_payload_size', 'start_time', 'end_time',
        'protocol_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flags',
        'version_ipv4', 'ihl_ipv4', 'type_of_service_ipv4', 'total_length_ipv4',
        'identification_ipv4', 'fragment_offset_ipv4', 'ttl_ipv4', 'header_checksum_ipv4', 'options_ipv4',
        'version_ipv6', 'traffic_class_ipv6', 'flow_label_ipv6', 'payload_length_ipv6', 'next_header_ipv6',
        'hop_limit_ipv6', 'mean_payload_length', 'median_payload_length', 'max_payload_length',
        'min_payload_length', 'std_payload_length', 'var_payload_length'
    ])
    
    # Convert categorical features to numerical
    if 'flags' in df.columns:
        le = LabelEncoder()
        df['flags'] = le.fit_transform(df['flags'].astype(str))
    if 'options_ipv4' in df.columns:
        df['options_ipv4'] = df['options_ipv4'].astype(str)
    
    # Impute missing values
    numeric_cols = df.select_dtypes(include=['number']).columns
    imputer = SimpleImputer(strategy='mean')
    df_imputed = imputer.fit_transform(df[numeric_cols])
    df_imputed = pd.DataFrame(df_imputed, columns=numeric_cols)
    
    # Make predictions
    predictions = rf_classifier.predict(df_imputed)
    
    # Add predictions to DataFrame
    df['prediction'] = predictions
    
    # Save predictions to CSV
    save_path = 'predictions.csv'
    df.to_csv(save_path, index=False)
    print("Predictions saved to:", save_path)

def capture_live_traffic_and_predict(duration=120):
    print(f"Capturing live traffic for {duration} seconds...")
    make_predictions_and_save()
    print("Prediction completed.")

if __name__ == "__main__":
    capture_live_traffic_and_predict(duration=120)