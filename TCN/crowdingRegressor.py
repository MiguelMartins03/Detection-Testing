import joblib
import pandas as pd
import numpy as np
import sys
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0' 
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import logging
logging.getLogger("tensorflow").setLevel(logging.ERROR) 
from tensorflow.keras.models import load_model

INPUT_CSV = 'sniffedData.csv'
SCALER_PATH = 'wifi_tcn_scaler.pkl'
MODEL_PATH = 'wifi_tcn_regressor.keras'
HISTORY_FILE = 'tcn_feature_history.csv'

TIME_STEPS = 3
NUM_FEATURES = 4
n_devices = 0

try:
    scaler = joblib.load(SCALER_PATH)
    tcn_model = load_model(MODEL_PATH)
except Exception as e:
    print(f"Failed to load ML models: {e}")
    sys.exit(1)

try:
    df_raw = pd.read_csv(INPUT_CSV)
    
    if not df_raw.empty:
        total_packets = len(df_raw)
        unique_macs = df_raw['MAC'].nunique()
        unique_fingerprints = df_raw['Fingerprint'].nunique()

        if unique_fingerprints == 0:
            packets_per_fingerprint = 0
        else:
            packets_per_fingerprint = total_packets / unique_fingerprints

        current_features = {
            'Total_Packets': total_packets,
            'Unique_MACs': unique_macs,
            'Unique_Fingerprints': unique_fingerprints,
            'Packets_Per_Fingerprint': packets_per_fingerprint
        }
        
        if os.path.exists(HISTORY_FILE):
            df_history = pd.read_csv(HISTORY_FILE)
            df_history = pd.concat([df_history, pd.DataFrame([current_features])], ignore_index=True)
        else:
            df_history = pd.DataFrame([current_features])
        
        if len(df_history) > TIME_STEPS:
            df_history = df_history.tail(TIME_STEPS).reset_index(drop=True)
            
        df_history.to_csv(HISTORY_FILE, index=False)

        pad_needed = TIME_STEPS - len(df_history)
        if pad_needed > 0:
            padding = pd.DataFrame([current_features] * pad_needed)
            df_sequence = pd.concat([padding, df_history], ignore_index=True)
        else:
            df_sequence = df_history

        feature_cols = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
        raw_sequence_array = df_sequence[feature_cols].values
        
        sequence_scaled = scaler.transform(raw_sequence_array)
        
        # Add the 4th dimension for the Conv2D (Channels = 1)
        X_live_reshaped = sequence_scaled.reshape(1, TIME_STEPS, NUM_FEATURES, 1)

        raw_prediction = tcn_model.predict(X_live_reshaped, verbose=0)[0][0]
        n_devices = max(0, int(np.round(raw_prediction)))

except pd.errors.EmptyDataError:
    n_devices = 0
except Exception as e:
    print(f"Error during ML prediction: {e}")
    n_devices = 0

print(f"{n_devices}")