import socket
import json
import time
import random
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- Configuration ---
HUB_IP = '127.0.0.1'
HUB_PORT = 9999
# --- UPDATED to match data.csv ---
SENSOR_ID = 'Temp-001'
SENSOR_TYPE = 'Temperature'
AES_KEY = b'ThisIsA-32-Byte-Key-For-AES-256!'
# Temperature generation settings
TEMP_MIN = 21.0  # minimum temp (°C)
TEMP_MAX = 35.0  # maximum temp (°C)

# Sending interval settings (seconds)
# The sensor will wait a random interval between INTERVAL_MIN and INTERVAL_MAX
INTERVAL_MIN = 3    # minimum seconds between sends
INTERVAL_MAX = 30   # maximum seconds between sends
# ---------------------

def encrypt_data(data_dict, key):
    data_bytes = json.dumps(data_dict).encode('utf-8')
    iv = os.urandom(16) 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

def run_sensor_simulation():
    print(f"Starting {SENSOR_ID} (temp range {TEMP_MIN}-{TEMP_MAX} °C)...")
    while True:
        try:
            # Generate a random temperature within the target range
            current_temp = round(random.uniform(TEMP_MIN, TEMP_MAX), 2)

            data = {
                'sensor_id': SENSOR_ID,
                'type': SENSOR_TYPE,
                'value': current_temp,
                'timestamp': time.time()
            }

            print(f"Sending: Temperature {current_temp}°C")
            encrypted_payload = encrypt_data(data, AES_KEY)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HUB_IP, HUB_PORT))
                s.sendall(encrypted_payload)

            # Sleep a random interval before sending the next reading
            sleep_for = random.uniform(INTERVAL_MIN, INTERVAL_MAX)
            time.sleep(sleep_for)
        except ConnectionRefusedError:
            print(f"Connection refused. Is the hub server running?")
            time.sleep(5)
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(2)
if __name__ == "__main__":
    run_sensor_simulation()
