
import socket
import json
import time
import threading
import pandas as pd
import joblib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import warnings

warnings.filterwarnings('ignore')

# --- Configuration ---
HOST_IP = '127.0.0.1'
HOST_PORT = 9999
BUFFER_SIZE = 1024
AES_KEY = b'ThisIsA-32-Byte-Key-For-AES-256!'
MODEL_PATH = '../model_pipeline.joblib'
ENCODER_PATH = '../label_encoder.joblib'
# ---------------------

# --- ML Model Loading ---
def load_ml_components(model_path, encoder_path):
    """Loads the trained model pipeline and label encoder."""
    try:
        model = joblib.load(model_path)
        encoder = joblib.load(encoder_path)
        print(f"Successfully loaded model from {model_path}")
        print(f"Successfully loaded encoder from {encoder_path}")
        print(f"Encoder classes: {encoder.classes_}")
        return model, encoder
    except FileNotFoundError:
        print("\n" + "="*50)
        print(f"FATAL ERROR: Model or encoder file not found.")
        print(f"Looked for: {model_path} and {encoder_path}")
        print("Please run the `train_model.py` script in the")
        print("`phase_1_model_training` folder first!")
        print("="*50 + "\n")
        return None, None
    except Exception as e:
        print(f"Error loading ML components: {e}")
        return None, None

def get_time_features(timestamp):
    """Derives Time_of_Day and Day_of_Week from a timestamp."""
    dt_object = datetime.fromtimestamp(timestamp)
    hour = dt_object.hour
    day = dt_object.weekday() # Monday=0, Sunday=6
    
    if 6 <= hour <= 18:
        time_of_day = 'Working_Hours' # Simplified from your data
    else:
        time_of_day = 'Night' # Simplified from your data
        
    if day < 5: # 0-4 are Monday-Friday
        day_of_week = 'Weekday'
    else: # 5-6 are Saturday-Sunday
        day_of_week = 'Weekend'
        
    return time_of_day, day_of_week

def process_and_predict(data_dict, model, encoder):
    """
    Processes a single raw data packet and returns a prediction.
    """
    try:
        # 1. Add derived time features
        time_of_day, day_of_week = get_time_features(data_dict['timestamp'])
        data_dict['Time_of_Day'] = time_of_day
        data_dict['Day_of_Week'] = day_of_week
        
        # 2. Rename keys to match training columns
        # Our sensor sends 'type', but model trained on 'Sensor_Type'
        data_dict['Sensor_ID'] = data_dict.pop('sensor_id')
        data_dict['Sensor_Type'] = data_dict.pop('type')
        data_dict['Value'] = data_dict.pop('value')
        
        # 3. Convert to DataFrame
        # The model pipeline expects a DataFrame
        input_df = pd.DataFrame([data_dict])
        
        # 4. Predict
        # model_pipeline.predict() returns a number (e.g., [0] or [1])
        prediction_encoded = model.predict(input_df)
        
        # 5. Decode Prediction
        # We use the encoder to turn the number back into a string
        prediction_label = encoder.inverse_transform(prediction_encoded)[0]
        
        return prediction_label, data_dict
        
    except Exception as e:
        print(f"[Prediction Error] Could not process packet: {e}")
        return None, data_dict

# --- Server Logic ---
def decrypt_data(encrypted_data, key):
    """Decrypts AES-256 (CBC) data."""
    try:
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        decrypted_data_bytes = unpad(decrypted_padded_data, AES.block_size)
        data_dict = json.loads(decrypted_data_bytes.decode('utf-8'))
        return data_dict
    except Exception as e:
        print(f"Decryption Error: {e}. Key may be wrong or data corrupt.")
        return None

def handle_client_connection(client_socket, client_address, model, encoder):
    """Handles a single client connection in a separate thread."""
    print(f"[New Connection] Accepted from {client_address[0]}:{client_address[1]}")
    try:
        while True:
            encrypted_data = client_socket.recv(BUFFER_SIZE)
            if not encrypted_data:
                break
                
            data = decrypt_data(encrypted_data, AES_KEY)
            
            if data and model and encoder:
                # This is the new, real prediction logic
                prediction, processed_data = process_and_predict(data, model, encoder)
                
                if prediction:
                    print(f"\n[Data Received] from {processed_data.get('Sensor_ID')}: {processed_data.get('Sensor_Type')}={processed_data.get('Value')}")
                    
                    if prediction == 'Anomalous':
                        print(f"!!! ALERT: ANOMALY DETECTED !!!")
                        print(f"    Sensor: {processed_data.get('Sensor_ID')}")
                        print(f"    Time: {datetime.fromtimestamp(processed_data.get('timestamp'))}")
                        print(f"    Value: {processed_data.get('Value')}")
                    else: # 'Normal'
                        print(f"[Status] System Normal. Prediction: {prediction}")

    except ConnectionResetError:
        print(f"[Connection Closed] Client {client_address[0]}:{client_address[1]} disconnected.")
    except Exception as e:
        print(f"Error handling client {client_address[0]}:{client_address[1]}: {e}")
    finally:
        client_socket.close()

def main():
    """Starts the main hub server."""
    model, encoder = load_ml_components(MODEL_PATH, ENCODER_PATH)
    
    if not model or not encoder:
        print("Exiting. ML components not loaded.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST_IP, HOST_PORT))
        server_socket.listen(5)
        print(f"--- Central Hub Server ---")
        print(f"Listening for connections on {HOST_IP}:{HOST_PORT}...")

        while True:
            client_sock, client_addr = server_socket.accept()
            client_handler = threading.Thread(
                target=handle_client_connection,
                args=(client_sock, client_addr, model, encoder),
                daemon=True
            )
            client_handler.start()

    except OSError as e:
        print(f"\n[Server Error] Could not bind to {HOST_IP}:{HOST_PORT}. Port in use?")
        print(f"Error details: {e}")
    except KeyboardInterrupt:
        print("\n[Shutdown] Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()

