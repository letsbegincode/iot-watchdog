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
SENSOR_ID = 'Motion-001'
SENSOR_TYPE = 'Motion'
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
    while True:
        try:
            # Simulate motion detected
            motion_detected = 1.0
            data = {
                'sensor_id': SENSOR_ID,
                'type': SENSOR_TYPE,
                'value': motion_detected,
                'timestamp': time.time()
            }
            print(f"Sending: Motion DETECTED (Value: {motion_detected})")
            encrypted_payload = encrypt_data(data, AES_KEY)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HUB_IP, HUB_PORT))
                s.sendall(encrypted_payload)
            
            time.sleep(random.randint(5, 15))

            # Simulate no motion
            motion_detected = 0.0
            data['value'] = motion_detected
            data['timestamp'] = time.time()
            print(f"Sending: Motion STOPPED (Value: {motion_detected})")
            encrypted_payload = encrypt_data(data, AES_KEY)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HUB_IP, HUB_PORT))
                s.sendall(encrypted_payload)

            time.sleep(random.randint(20, 60))
        except ConnectionRefusedError:
            print(f"Connection refused. Is the hub server running?")
            time.sleep(10)
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(5)
if __name__ == "__main__":
    run_sensor_simulation()