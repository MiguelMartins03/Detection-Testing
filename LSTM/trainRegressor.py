import pandas as pd
import numpy as np
import joblib
import os
from sklearn.preprocessing import StandardScaler
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Input, LSTM, Dense, Dropout

# INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_time_sensitive.csv'
# FEATURE_COLS = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# SCALER_FILENAME = 'wifi_lstm_scaler.pkl'
# MODEL_FILENAME = 'wifi_lstm_regressor.keras'
INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_burst_time_sensitive.csv'
FEATURE_COLS = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
SCALER_FILENAME = 'wifi_lstm_scaler_burst.pkl'
MODEL_FILENAME = 'wifi_lstm_regressor_burst.keras'
# INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_15min_time_sensitive.csv'
# FEATURE_COLS = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# SCALER_FILENAME = 'wifi_lstm_scaler_15min.pkl'
# MODEL_FILENAME = 'wifi_lstm_regressor_15min.keras'
# INPUT_DATASET = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_15min_burst_time_sensitive.csv'
# FEATURE_COLS = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
# SCALER_FILENAME = 'wifi_lstm_scaler_15min_burst.pkl'
# MODEL_FILENAME = 'wifi_lstm_regressor_15min_burst.keras'

# How many 5-minute intervals the LSTM looks at simultaneously to make 1 guess
# 3 steps = 15 minutes of context
TIME_STEPS = 3 

print(f"Loading {INPUT_DATASET}...")
df = pd.read_csv(INPUT_DATASET)

X_raw = df[FEATURE_COLS].values
y_raw = df['Target_Device_Count'].values

# 1. Scale Data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_raw)

# 2. Create Sequences (Sliding Windows)
# Transforms 2D tabular data into 3D sequences: (Samples, Time_Steps, Features)
def create_sequences(X, y, time_steps):
    Xs, ys = [], []
    for i in range(len(X) - time_steps + 1):
        Xs.append(X[i:(i + time_steps)])
        # The target is the device count at the LAST step of the sequence
        ys.append(y[i + time_steps - 1]) 
    return np.array(Xs), np.array(ys)

X_seq, y_seq = create_sequences(X_scaled, y_raw, TIME_STEPS)


print(f"\nBuilding LSTM Neural Network... (Input Shape: {X_seq.shape})")
model = Sequential([
    # The LSTM layer reads the 3 time steps chronologically
    Input(shape=(TIME_STEPS, len(FEATURE_COLS))),
    LSTM(32, activation='tanh'),
    
    Dropout(0.2), # Prevent overfitting
    
    # Standard Dense layers to interpret the LSTM's conclusion
    Dense(16, activation='relu'),
    Dense(1, activation='linear')
])

model.compile(optimizer='adam', loss='mse', metrics=['mae'])

print("Training Model...")
history = model.fit(
    X_seq, y_seq,
    epochs=150,
    batch_size=32,
    validation_split=0.2,
    verbose=1
)

print("\nTraining Complete!")

# Save Scaler and Model
joblib.dump(scaler, SCALER_FILENAME)
model.save(MODEL_FILENAME)
print(f"\nSaved scaler to {SCALER_FILENAME}")
print(f"Saved model to {MODEL_FILENAME}")