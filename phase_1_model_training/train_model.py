import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
import joblib
import warnings

warnings.filterwarnings('ignore')

# ============================================================
# 1. Load Data
# ============================================================
filename = 'data.csv'
try:
    data = pd.read_csv(filename)
    print(f"Successfully loaded '{filename}'")
except FileNotFoundError:
    print(f"Error: File '{filename}' not found.")
    print("Please make sure 'data.csv' is in the same directory.")
    exit()
except Exception as e:
    print(f"An error occurred: {e}")
    exit()

# ============================================================
# 2. Define Features and Target
# ============================================================
# We train on all data except the Timestamp and Label
X = data.drop(['Timestamp', 'Label'], axis=1)
y = data['Label']

# Encode the text labels (e.g., "Normal", "Anomalous") into numbers (0, 1)
le = LabelEncoder()
y_encoded = le.fit_transform(y)

print(f"Label mapping: {dict(zip(le.classes_, le.transform(le.classes_)))}")

# ============================================================
# 3. Define Preprocessing Pipeline
# ============================================================
# These are the columns from your data.csv
categorical_features = ['Sensor_ID', 'Sensor_Type', 'Time_of_Day', 'Day_of_Week']
numerical_features = ['Value']

# Create the preprocessor from your friend's script
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), numerical_features),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ])

# ============================================================
# 4. Create and Train the Full Model Pipeline
# ============================================================
# We bundle the preprocessor and the classifier into one "Pipeline"
# This makes prediction much easier in the hub.
model_pipeline = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('classifier', RandomForestClassifier(random_state=42))
])

print("\nStarting model training...")
# We train the pipeline on the *entire* dataset
model_pipeline.fit(X, y_encoded)
print("Model training complete.")

# ============================================================
# 5. Save the Model and Encoder
# ============================================================
# We save the *entire pipeline* to the parent directory
model_path = '../model_pipeline.joblib'
joblib.dump(model_pipeline, model_path)
print(f"Model pipeline saved to: {model_path}")

# We also save the label encoder so the hub can turn 0/1 back into "Normal"/"Anomalous"
encoder_path = '../label_encoder.joblib'
joblib.dump(le, encoder_path)
print(f"Label encoder saved to: {encoder_path}")

