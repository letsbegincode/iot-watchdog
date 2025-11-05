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
# ---------------------

def encrypt_data(data_dict, key):
    data_bytes = json.dumps(data_dict).encode('utf-8')
    iv = os.urandom(16) 
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

def run_sensor_simulation():
    print(f"Starting {SENSOR_ID}...")
    current_temp = 21.5 
    while True:
        try:
            temp_change = random.uniform(-0.5, 0.5)
            current_temp = round(current_temp + temp_change, 2)
            if current_temp < 18.0: current_temp = 18.0
            if current_temp > 25.0: current_temp = 25.0

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
            
            time.sleep(60) # Send temp every minute
        except ConnectionRefusedError:
            print(f"Connection refused. Is the hub server running?")
            time.sleep(10)
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(5)
if __name__ == "__main__":
    run_sensor_simulation()
