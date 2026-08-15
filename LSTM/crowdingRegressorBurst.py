import joblib
import pandas as pd
import numpy as np
import sys
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
from tensorflow.keras.models import load_model

FEATURE_COLS = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
INPUT_CSV = 'sniffedData.csv'
SCALER_PATH = 'wifi_lstm_scaler.pkl'
MODEL_PATH = 'wifi_lstm_regressor.keras'
HISTORY_FILE = 'lstm_feature_history.csv'

TIME_STEPS = 3
n_devices = 0

try:
    scaler = joblib.load(SCALER_PATH)
    lstm_model = load_model(MODEL_PATH)
except Exception as e:
    print(f"Failed to load ML models: {e}")
    sys.exit(1)

try:
    df_raw = pd.read_csv(INPUT_CSV)
    
    if not df_raw.empty:
        df_raw = df_raw.sort_values(by='Time')

        total_packets = len(df_raw)
        unique_macs = df_raw['MAC'].nunique()
        unique_fingerprints = df_raw['Fingerprint'].nunique()

        last_seen_macs = {}
        total_bursts = 0
        
        for _, row in df_raw.iterrows():
            mac = row['MAC']
            time_val = row['Time']
            seq = row['Seq']
            
            is_new_burst = True
            
            if mac in last_seen_macs:
                last_pkt = last_seen_macs[mac]
                time_diff = time_val - last_pkt['time']
                seq_diff = (seq - last_pkt['seq']) % 4096 
                
                if time_diff <= 3.0 and seq_diff <= 15:
                    is_new_burst = False
            
            last_seen_macs[mac] = {'time': time_val, 'seq': seq}
            if is_new_burst:
                total_bursts += 1

        if unique_fingerprints == 0:
            packets_per_fingerprint = 0
            bursts_per_fingerprint = 0
        else:
            packets_per_fingerprint = total_packets / unique_fingerprints
            bursts_per_fingerprint = total_bursts / unique_fingerprints

        # 1. Current Features
        current_features = {
            'Total_Packets': total_packets,
            'Total_Bursts': total_bursts,
            'Unique_MACs': unique_macs,
            'Unique_Fingerprints': unique_fingerprints,
            'Packets_Per_Fingerprint': packets_per_fingerprint,
            'Bursts_Per_Fingerprint': bursts_per_fingerprint
        }
        
        # 2. Manage History Buffer
        if os.path.exists(HISTORY_FILE):
            df_history = pd.read_csv(HISTORY_FILE)
            # Concatenate only if history already exists and is not empty
            df_history = pd.concat([df_history, pd.DataFrame([current_features])], ignore_index=True)
        else:
            # If no history exists, create a brand new DataFrame directly with the first row
            df_history = pd.DataFrame([current_features])
        
        # Keep only the last TIME_STEPS rows
        if len(df_history) > TIME_STEPS:
            df_history = df_history.tail(TIME_STEPS).reset_index(drop=True)
            
        # Save back to disk for the next 5-minute cron run
        df_history.to_csv(HISTORY_FILE, index=False)

        # 3. Prepare for LSTM
        # If we just booted up and don't have 15 mins of history yet, we duplicate the current row to fill the sequence
        pad_needed = TIME_STEPS - len(df_history)
        if pad_needed > 0:
            padding = pd.DataFrame([current_features] * pad_needed)
            df_sequence = pd.concat([padding, df_history], ignore_index=True)
        else:
            df_sequence = df_history

        raw_sequence_array = df_sequence[FEATURE_COLS].values

        # Scale the 3x4 matrix
        sequence_scaled = scaler.transform(raw_sequence_array)
        
        # Reshape to 3D: (1 sample, 3 time steps, 4 features)
        X_live_reshaped = sequence_scaled.reshape(1, TIME_STEPS, sequence_scaled.shape[1])

        # 4. Predict
        raw_prediction = lstm_model.predict(X_live_reshaped, verbose=0)[0][0]
        n_devices = max(0, int(np.round(raw_prediction)))

except pd.errors.EmptyDataError:
    n_devices = 0
except Exception as e:
    print(f"Error during ML prediction: {e}")
    n_devices = 0

print(n_devices)