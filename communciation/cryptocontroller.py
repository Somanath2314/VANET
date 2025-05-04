import traci
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib

# Start SUMO GUI
sumoCmd = ["sumo-gui", "-c", "simple.sumocfg"]
traci.start(sumoCmd)

COMM_COLOR = (0, 255, 0, 255)    # Green for communication
DEFAULT_COLOR = (255, 0, 0, 255)  # Red for default

# ------------------------
# Helper: Get stopped vehicles near TLS
# ------------------------
def get_stopped_vehicles_near_tls(tls_id):
    lane_ids = traci.trafficlight.getControlledLanes(tls_id)
    stopped_vehicles = []
    for lane in lane_ids:
        veh_ids = traci.lane.getLastStepVehicleIDs(lane)
        for vid in veh_ids:
            speed = traci.vehicle.getSpeed(vid)
            if speed < 0.1:
                stopped_vehicles.append(vid)
    return stopped_vehicles

# ------------------------
# Post-Quantum Crypto Simulation
# ------------------------

vehicle_shared_keys = {}

def get_shared_secret(sender, receiver):
    # Generate same shared secret for both directions using vehicle IDs
    ids = "_".join(sorted([sender, receiver]))
    return hashlib.sha256(ids.encode()).digest()  # 32 bytes

def pqc_handshake(sender, receiver):
    shared_secret = get_shared_secret(sender, receiver)
    vehicle_shared_keys[(sender, receiver)] = shared_secret
    vehicle_shared_keys[(receiver, sender)] = shared_secret

def send_secure_message(sender, receiver, message):
    if (sender, receiver) not in vehicle_shared_keys:
        pqc_handshake(sender, receiver)
    key = vehicle_shared_keys[(sender, receiver)][:16]  # AES-128
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ct

def receive_secure_message(receiver, sender, encrypted_msg):
    key = vehicle_shared_keys[(receiver, sender)][:16]
    iv = encrypted_msg[:16]
    ct = encrypted_msg[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# ------------------------
# Main Loop
# ------------------------

step = 0
already_communicated = set()

while traci.simulation.getMinExpectedNumber() > 0:
    traci.simulationStep()
    
    # Reset all vehicle colors
    for veh_id in traci.vehicle.getIDList():
        traci.vehicle.setColor(veh_id, DEFAULT_COLOR)

    tls_state = traci.trafficlight.getRedYellowGreenState("n1")

    if 'r' in tls_state:  # If red light present
        stopped_vehicles = get_stopped_vehicles_near_tls("n1")
        if len(stopped_vehicles) >= 2:
            v1, v2 = stopped_vehicles[:2]
            pair = tuple(sorted((v1, v2)))
            if pair not in already_communicated:
                encrypted_msg = send_secure_message(v2, v1, "RED LIGHT ALERT")
                decrypted_msg = receive_secure_message(v1, v2, encrypted_msg)
                
                print(f"[Step {step}] 🛡️ Secure Communication Triggered:")
                print(f"  🚗 {v1} decrypted: '{decrypted_msg}' from {v2}")

                already_communicated.add(pair)

            traci.vehicle.setColor(v1, COMM_COLOR)
            traci.vehicle.setColor(v2, COMM_COLOR)

    step += 1

traci.close()
