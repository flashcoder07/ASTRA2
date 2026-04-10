import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Mapping of specific attacks to broad categories
LABEL_MAPPING = {
    # Normal
    'BenignTraffic': 'Normal',
    
    # DDoS
    'DDoS-ICMP_Flood': 'DDoS',
    'DDoS-UDP_Flood': 'DDoS',
    'DDoS-TCP_Flood': 'DDoS',
    'DDoS-PSHACK_Flood': 'DDoS',
    'DDoS-RSTFINFlood': 'DDoS',
    'DDoS-SYN_Flood': 'DDoS',
    'DDoS-SynonymousIP_Flood': 'DDoS',
    'DoS-UDP_Flood': 'DDoS',
    'DoS-TCP_Flood': 'DDoS',
    'DoS-SYN_Flood': 'DDoS',
    'Mirai-greeth_flood': 'DDoS',
    'Mirai-udpplain': 'DDoS',
    'Mirai-greip_flood': 'DDoS',
    'DDoS-ICMP_Fragmentation': 'DDoS',
    'DDoS-UDP_Fragmentation': 'DDoS',
    'DDoS-ACK_Fragmentation': 'DDoS',
    'DoS-HTTP_Flood': 'DDoS',
    'DDoS-HTTP_Flood': 'DDoS',
    'DDoS-SlowLoris': 'DDoS',
    
    # Brute Force
    'DictionaryBruteForce': 'BruteForce',
    
    # Port Scan
    'Recon-HostDiscovery': 'PortScan',
    'Recon-OSScan': 'PortScan',
    'Recon-PortScan': 'PortScan',
    'VulnerabilityScan': 'PortScan',
    'Recon-PingSweep': 'PortScan',
    
    # Other (to be dropped or handled)
    'MITM-ArpSpoofing': 'Other',
    'DNS_Spoofing': 'Other',
    'SqlInjection': 'Other',
    'Backdoor_Malware': 'Other',
    'XSS': 'Other',
    'BrowserHijacking': 'Other',
    'CommandInjection': 'Other',
    'Uploading_Attack': 'Other'
}

# Features to keep - based on what we can easily derive from live packet capture
# Duration -> flow_duration
# Protocol Type -> protocol
# Rate -> calculated from packets/duration
# Srate -> calculated from bytes/duration (proxy)
# Features to keep - expanded set
SELECTED_FEATURES = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate',
    'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
    'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count',
    'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP',
    'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT',
    'Number', 'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight'
]

def load_data(path=None, sample_size=200000, target_per_class=5000):
    """
    Load the CICIoT2023 dataset with a BALANCED per-class sampling strategy.

    Strategy:
      - Load a large chunk of the CSV (sample_size rows) to get class variety.
      - Take ALL available BruteForce and PortScan rows (they are rare).
      - Cap DDoS and Normal at target_per_class each.
      - Concatenate and shuffle to produce a balanced training set.

    Args:
        path (str): Path to dataset CSV. If None, uses default kagglehub cache.
        sample_size (int): Initial rows to load before class-stratified sampling.
        target_per_class (int): Max rows per class for DDoS and Normal.
    """
    if path is None:
        base_path = os.path.expanduser("~/.cache/kagglehub/datasets/himadri07/ciciot2023/versions/1/CICIOT23/train/train.csv")
        if os.path.exists(base_path):
            path = base_path
        else:
            raise FileNotFoundError("Dataset path not provided and not found in default cache location.")

    print(f"Loading data from {path} (Initial scan: {sample_size} rows)...")

    # Load a large chunk to maximise minority-class coverage
    df = pd.read_csv(path, nrows=sample_size)

    # Map labels
    print("Mapping labels...")
    df['mapped_label'] = df['label'].map(LABEL_MAPPING)

    # Keep only known classes
    df = df[df['mapped_label'].isin(['Normal', 'DDoS', 'BruteForce', 'PortScan'])].copy()

    # ── Balanced per-class sampling ─────────────────────────────────────
    classes = {label: grp for label, grp in df.groupby('mapped_label')}

    sampled_parts = []
    for label, grp in classes.items():
        if label in ('BruteForce', 'PortScan'):
            # Rare classes — take everything available
            sampled_parts.append(grp)
            print(f"  {label}: taking ALL {len(grp)} rows")
        else:
            # Common classes — cap at target_per_class
            n = min(len(grp), target_per_class)
            sampled_parts.append(grp.sample(n=n, random_state=42))
            print(f"  {label}: sampled {n} / {len(grp)} rows")

    df = pd.concat(sampled_parts).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\nBalanced dataset shape: {df.shape}")
    print(f"Label distribution:\n{df['mapped_label'].value_counts()}")

    # Feature selection
    missing_cols = [col for col in SELECTED_FEATURES if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing expected columns in dataset: {missing_cols}")

    X = df[SELECTED_FEATURES].copy()
    y = df['mapped_label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    return X_train, X_test, y_train, y_test, SELECTED_FEATURES


def get_label_mapping():
    return LABEL_MAPPING
