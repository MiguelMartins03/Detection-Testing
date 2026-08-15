import os
import sys
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
from sklearn.metrics import mean_absolute_error, mean_squared_error

# Suppress TensorFlow logging warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
from tensorflow.keras.models import load_model

# --- TCN ---
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_time_sensitive.csv'
# feature_cols = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# SCALER_PATH = '/home/kali/Detection_Testing/TCN/wifi_tcn_scaler.pkl'
# MODEL_PATH = '/home/kali/Detection_Testing/TCN/wifi_tcn_regressor.keras'
# OUTPUT_IMAGE = 'Plots/TCN_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_burst_time_sensitive.csv'
# feature_cols = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
# SCALER_PATH = '/home/kali/Detection_Testing/TCN/wifi_tcn_scaler_burst.pkl'
# MODEL_PATH = '/home/kali/Detection_Testing/TCN/wifi_tcn_regressor_burst.keras'
# OUTPUT_IMAGE = 'Plots/TCN_burst_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_15min_time_sensitive.csv'
# feature_cols = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# SCALER_PATH = '/home/kali/Detection_Testing/TCN/wifi_tcn_scaler_15min.pkl'
# MODEL_PATH = '/home/kali/Detection_Testing/TCN/wifi_tcn_regressor_15min.keras'
# OUTPUT_IMAGE = 'Plots/TCN_15min_prediction_scatter_plot.png'
INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_15min_burst_time_sensitive.csv'
feature_cols = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
SCALER_PATH = '/home/kali/Detection_Testing/TCN/wifi_tcn_scaler_15min_burst.pkl'
MODEL_PATH = '/home/kali/Detection_Testing/TCN/wifi_tcn_regressor_15min_burst.keras'
OUTPUT_IMAGE = 'Plots/TCN_15min_burst_prediction_scatter_plot.png'
# --- LSTM ---
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_time_sensitive.csv'
# feature_cols = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# SCALER_PATH = '/home/kali/Detection_Testing/LSTM/wifi_lstm_scaler.pkl'
# MODEL_PATH = '/home/kali/Detection_Testing/LSTM/wifi_lstm_regressor.keras'
# OUTPUT_IMAGE = 'Plots/LSTM_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_burst_time_sensitive.csv'
# feature_cols = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
# SCALER_PATH = '/home/kali/Detection_Testing/LSTM/wifi_lstm_scaler_burst.pkl'
# MODEL_PATH = '/home/kali/Detection_Testing/LSTM/wifi_lstm_regressor_burst.keras'
# OUTPUT_IMAGE = 'Plots/LSTM_burst_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_15min_time_sensitive.csv'
# feature_cols = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# SCALER_PATH = '/home/kali/Detection_Testing/LSTM/wifi_lstm_scaler_15min.pkl'
# MODEL_PATH = '/home/kali/Detection_Testing/LSTM/wifi_lstm_regressor_15min.keras'
# OUTPUT_IMAGE = 'Plots/LSTM_15min_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_15min_burst_time_sensitive.csv'
# feature_cols = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
# SCALER_PATH = '/home/kali/Detection_Testing/LSTM/wifi_lstm_scaler_15min_burst.pkl'
# MODEL_PATH = '/home/kali/Detection_Testing/LSTM/wifi_lstm_regressor_15min_burst.keras'
# OUTPUT_IMAGE = 'Plots/LSTM_15min_burst_prediction_scatter_plot.png'
TIME_STEPS = 3

print(f"Loading Scaler from {SCALER_PATH}...")
try:
    scaler = joblib.load(SCALER_PATH)
except Exception as e:
    print(f"Failed to load scaler: {e}")
    sys.exit(1)

print(f"Loading Model from {MODEL_PATH}...")
try:
    model = load_model(MODEL_PATH)
except Exception as e:
    print(f"Failed to load TensorFlow model: {e}")
    sys.exit(1)

print(f"Loading Data from {INPUT_CSV}...")
try:
    df = pd.read_csv(INPUT_CSV)
except FileNotFoundError:
    print(f"Error: Could not find file {INPUT_CSV}")
    sys.exit(1)

if df.empty:
    print("CSV is empty. Nothing to verify.")
    sys.exit(0)

# ==========================================
# 1. DATA PREPARATION (Sequence Building)
# ==========================================

# Scale the data using the loaded scaler
df[feature_cols] = scaler.transform(df[feature_cols])

Xs, ys = [], []

# Safely build sequences without crossing scenario boundaries
scenario_starts = df.index[df['Interval_ID'] == 0].tolist()
scenario_starts.append(len(df))

for i in range(len(scenario_starts) - 1):
    start_idx = scenario_starts[i]
    end_idx = scenario_starts[i+1]
    
    scenario_df = df.iloc[start_idx:end_idx]
    
    if len(scenario_df) >= TIME_STEPS:
        X_vals = scenario_df[feature_cols].values
        y_vals = scenario_df['Target_Device_Count'].values
        
        for j in range(len(scenario_df) - TIME_STEPS + 1):
            Xs.append(X_vals[j:(j + TIME_STEPS)])
            # The target is the count at the end of the sequence
            ys.append(y_vals[j + TIME_STEPS - 1])

X_seq = np.array(Xs)
y_true = np.array(ys)

print(f"Successfully built {len(X_seq)} chronological sequences for testing.")

# ==========================================
# 2. RUN PREDICTIONS
# ==========================================
print("Running predictions...")
raw_predictions = model.predict(X_seq, verbose=0).flatten()
y_pred = np.maximum(0, np.round(raw_predictions)).astype(int)

# 3. Calculate Quick Metrics for Console
mae = mean_absolute_error(y_true, y_pred)
rmse = np.sqrt(mean_squared_error(y_true, y_pred))
print("\n--- RESULTS ---")
print(f"Total Sequences Tested: {len(X_seq)}")
print(f"MAE : {mae:.2f} devices")
print(f"RMSE: {rmse:.2f} devices")

# ==========================================
# 4. PLOTTING THE DATA
# ==========================================
print("\nGenerating plot...")
plt.figure(figsize=(24, 16))

# Plot the scatter points
plt.scatter(y_true, y_pred, color='blue', alpha=0.3, edgecolor='k', label='Model Predictions')

# Plot the "Ideal/Perfect" line (y = x)
plt.plot([y_true.min(), y_true.max()], [y_true.min(), y_true.max()], color='red', linestyle='--', linewidth=2, label='Perfect Prediction (y=x)')

# Formatting the graph
plt.title('Predicted vs. Actual Device Count', fontsize=16, fontweight='bold')
plt.xlabel('Actual Device Count (Ground Truth)', fontsize=14)
plt.ylabel('Predicted Device Count (Model Output)', fontsize=14)
plt.grid(True, linestyle=':', alpha=0.7)
plt.legend(fontsize=12)

# Save the plot
plt.savefig(OUTPUT_IMAGE, dpi=300, bbox_inches='tight')
print(f"Plot saved successfully as '{OUTPUT_IMAGE}'")