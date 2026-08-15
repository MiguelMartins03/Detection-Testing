import pandas as pd
import numpy as np
import joblib
import os
from sklearn.preprocessing import StandardScaler
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0' 
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Input, Conv2D, ZeroPadding2D, Flatten, Dense, Dropout

INPUT_DATASET = 'C:\\Users\\migue\\Desktop\\ML\\regression_dataset_time_sensitive.csv'
FEATURE_COLS = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# INPUT_DATASET = 'C:\\Users\\migue\\Desktop\\ML\\regression_dataset_burst_time_sensitive.csv'
# FEATURE_COLS = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
# INPUT_DATASET = 'C:\\Users\\migue\\Desktop\\ML\\regression_dataset_15min_time_sensitive.csv'
# FEATURE_COLS = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# INPUT_DATASET = 'C:\\Users\\migue\\Desktop\\ML\\regression_dataset_15min_burst_time_sensitive.csv'
# FEATURE_COLS = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
SCALER_FILENAME = 'wifi_tcn_scaler.pkl'
MODEL_FILENAME = 'wifi_tcn_regressor.keras'

TIME_STEPS = 3 

print(f"Loading {INPUT_DATASET}...")
df = pd.read_csv(INPUT_DATASET)

NUM_FEATURES = len(FEATURE_COLS)

# 1. Scale Data
scaler = StandardScaler()
df[FEATURE_COLS] = scaler.fit_transform(df[FEATURE_COLS])

# 2. Safely Create Sequences
Xs, ys = [], []
scenario_starts = df.index[df['Interval_ID'] == 0].tolist()
scenario_starts.append(len(df))

for i in range(len(scenario_starts) - 1):
    start_idx = scenario_starts[i]
    end_idx = scenario_starts[i+1]
    
    scenario_df = df.iloc[start_idx:end_idx]
    
    if len(scenario_df) >= TIME_STEPS:
        X_vals = scenario_df[FEATURE_COLS].values
        y_vals = scenario_df['Target_Device_Count'].values
        
        for j in range(len(scenario_df) - TIME_STEPS + 1):
            Xs.append(X_vals[j:(j + TIME_STEPS)])
            ys.append(y_vals[j + TIME_STEPS - 1])

X_seq = np.array(Xs)
y_seq = np.array(ys)

# 3. Reshape for Conv2D: (Samples, Time, Features, Channels)
# e.g., (24000, 3, 4, 1)
X_seq_2d = X_seq.reshape(X_seq.shape[0], TIME_STEPS, NUM_FEATURES, 1)

indices = np.arange(len(X_seq_2d))
np.random.shuffle(indices)
X_train = X_seq_2d[indices]
y_train = y_seq[indices]

print(f"\nBuilding 2D TCN... (Input Shape: {X_train.shape})")
model = Sequential([
    Input(shape=(TIME_STEPS, NUM_FEATURES, 1)),
    
    # --- TCN BLOCK 1 (Dilation = 1) ---
    # Manual Causal Padding: Add 1 row of zeros to the TOP of the time axis.
    # Format: ((top, bottom), (left, right))
    ZeroPadding2D(padding=((1, 0), (0, 0))),
    
    # Conv2D: Kernel height=2 (Time), width=(Features). 
    # Because width is 4, it instantly collapses the 4 columns into 1!
    Conv2D(filters=32, kernel_size=(2, len(FEATURE_COLS)), activation='relu', padding='valid'),
    
    # --- TCN BLOCK 2 (Dilation = 2) ---
    # Manual Causal Padding for dilation 2: Add 2 rows of zeros to the TOP
    ZeroPadding2D(padding=((2, 0), (0, 0))),
    
    # Conv2D: Because the previous layer collapsed the features, the width is now 1.
    # We set dilation_rate on the Time axis (Y) to 2, and X to 1.
    Conv2D(filters=32, kernel_size=(2, 1), dilation_rate=(2, 1), activation='relu', padding='valid'),
    
    Flatten(),
    Dense(32, activation='relu'),
    Dropout(0.2),
    Dense(16, activation='relu'),
    Dense(1, activation='linear')
])

model.compile(optimizer='adam', loss='mse', metrics=['mae'])

print("Training Model...")
model.fit(
    X_train, y_train,
    epochs=150,
    batch_size=32,
    validation_split=0.2,
    verbose=1
)

joblib.dump(scaler, SCALER_FILENAME)
model.save(MODEL_FILENAME)
print(f"\nSaved scaler to {SCALER_FILENAME}")
print(f"Saved model to {MODEL_FILENAME}")