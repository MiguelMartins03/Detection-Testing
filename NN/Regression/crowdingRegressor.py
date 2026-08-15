import joblib
import pandas as pd
import numpy as np
import sys

INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/sniffedData.csv'
MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor.pkl'

USE_HP_FILTER = False
HISTORY_FILE = '/home/kali/Detection_Testing/NN/Regression/prediction_history.txt'
HP_LAMBDA = 1000

n_devices = 0

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Failed to load NN model: {e}")
    sys.exit(1)

# Regression
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

        X_live = pd.DataFrame([{
            'Total_Packets': total_packets,
            'Unique_MACs': unique_macs,
            'Unique_Fingerprints': unique_fingerprints,
            'Packets_Per_Fingerprint': packets_per_fingerprint
        }])

        raw_prediction = model.predict(X_live)[0]

        if USE_HP_FILTER:
            # 1. Save current raw prediction to history
            with open(HISTORY_FILE, 'a') as f:
                f.write(f"{raw_prediction}\n")
            
            # 2. Load the entire history
            history = np.loadtxt(HISTORY_FILE)
            
            # 3. Ensure history is an array (fixes bug if file only has 1 line)
            if history.ndim == 0:
                history = np.array([history])
                
            # 4. HP Filter requires at least 4 data points to draw a proper curve
            if len(history) >= 4:
                import statsmodels.api as sm
                
                # Apply the filter. It returns the 'cycle' (noise) and 'trend' (smoothed line)
                cycle, trend = sm.tsa.filters.hpfilter(history, lamb=HP_LAMBDA)
                
                # We want the trend value of the CURRENT (latest) interval
                smoothed_prediction = trend[-1]
                n_devices = max(0, int(np.round(smoothed_prediction)))
            else:
                # Not enough data yet, just use the raw prediction
                n_devices = max(0, int(np.round(raw_prediction)))
                
        else:
            # HP Filter is disabled. Just use raw prediction.
            n_devices = max(0, int(np.round(raw_prediction)))

except pd.errors.EmptyDataError:
    n_devices = 0
except Exception as e:
    print(f"Error during ML prediction: {e}")
    n_devices = 0

print(n_devices)