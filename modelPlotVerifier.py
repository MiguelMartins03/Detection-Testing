import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import mean_absolute_error, root_mean_squared_error
import sys

# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_fing_20-20_300.csv'
# MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor.pkl'
# feature_cols = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# OUTPUT_IMAGE = 'Plots/NN_4feat_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_fing_20-20_burst_300.csv'
# MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor_burst.pkl'
# feature_cols = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
# OUTPUT_IMAGE = 'Plots/NN_burst_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_fing_20-20_ratios_300.csv'
# MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor_ratios.pkl'
# feature_cols = ['Unique_Fingerprints', 'Packets_Per_Fingerprint', 'MACs_Per_Fingerprint']
# OUTPUT_IMAGE = 'Plots/NN_ratios_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_fing_20-20_burst_ratios_300.csv'
# MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor_burst_ratios.pkl'
# feature_cols = ['Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint', 'MACs_Per_Fingerprint']
# OUTPUT_IMAGE = 'Plots/NN_ratios_burst_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_20min_300.csv'
# MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor_20m.pkl'
# feature_cols = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# OUTPUT_IMAGE = Plots/'NN_20min_prediction_scatter_plot.png'
INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_20min_burst_300.csv'
MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor_20m_burst.pkl'
feature_cols = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
OUTPUT_IMAGE = 'Plots/NN_20min_burst_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_15min_300.csv'
# MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor_15m.pkl'
# feature_cols = ['Total_Packets', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint']
# OUTPUT_IMAGE = 'Plots/NN_15min_prediction_scatter_plot.png'
# INPUT_CSV = '/home/kali/Detection_Testing/NN/Regression/regression_dataset_15min_burst_300.csv'
# MODEL_PATH = '/home/kali/Detection_Testing/NN/Regression/wifi_crowd_regressor_15m_burst.pkl'
# feature_cols = ['Total_Packets', 'Total_Bursts', 'Unique_MACs', 'Unique_Fingerprints', 'Packets_Per_Fingerprint', 'Bursts_Per_Fingerprint']
# OUTPUT_IMAGE = 'Plots/NN_15min_burst_prediction_scatter_plot.png'

print(f"Loading Model from {MODEL_PATH}...")
try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Failed to load ML model: {e}")
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

# 1. Extract Features and Ground Truth
X = df[feature_cols]
y_true = df['Target_Device_Count']

# 2. Get Predictions
print("Running predictions...")
raw_predictions = model.predict(X)
y_pred = np.maximum(0, np.round(raw_predictions)).astype(int)

# 3. Calculate Quick Metrics for Console
mae = mean_absolute_error(y_true, y_pred)
rmse = root_mean_squared_error(y_true, y_pred)
print("\n--- RESULTS ---")
print(f"Total Intervals Tested: {len(df)}")
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

# Save the plot as an image file
plt.savefig(OUTPUT_IMAGE, dpi=300, bbox_inches='tight')
print(f"Plot saved successfully as '{OUTPUT_IMAGE}'")