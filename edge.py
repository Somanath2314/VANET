#!/usr/bin/env python3
"""
edge.py: 
  - Launches SUMO via TraCI 
  - Each simulation step, reads induction loop counts (per sensor) 
  - Controls traffic light based on sensor counts
  - Encrypts the JSON report with AES-GCM 
  - Sends the ciphertext over UDP to the fog at localhost:5005
"""

import os
import sys
import json
import socket
import traci
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Global state for tracking how long each approach detector has been 'red'
approach_red_durations = {
    "north": 0,
    "south": 0,
    "east": 0,
    "west": 0
}

# ————————————————
# 1) SUMO / TraCI setup
# ————————————————
# Make sure SUMO's tools are on PYTHONPATH:
if 'SUMO_HOME' not in os.environ:
    print("Error: please set SUMO_HOME to your SUMO installation directory.")
    sys.exit(1)

tools_dir = os.path.join(os.environ['SUMO_HOME'], 'tools')
sys.path.append(tools_dir)

# Import TraCI after appending tools
import traci

# SUMO binary (use 'sumo-gui' or 'sumo' depending on whether you want a window)
SUMO_BINARY = "sumo-gui"   # Changed to sumo-gui to see the simulation

# Path to the configuration file
SUMO_CONFIG = "configs/intersection.sumocfg"

# ————————————————
# 2) Encryption setup (AES-GCM with a 16-byte key)
# ————————————————
KEY = b'0123456789abcdef'   # 16-byte (128-bit) symmetric key; keep this secret!

def encrypt_report(report_dict):
    """
    Encrypt a JSON-serializable dictionary with AES-GCM.
    Returns: nonce || tag || ciphertext bytes
    """
    plaintext = json.dumps(report_dict).encode('utf-8')
    cipher = AES.new(KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

# ————————————————
# 3) UDP socket (to send to fog)
# ————————————————
UDP_IP = "127.0.0.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# ————————————————
# 4) Traffic Light Control
# ————————————————
def get_sensor_counts():
    # Get counts from area detectors that cover entire approaches
    # Updated to use traci.areal and new detector IDs
    north_count = traci.lanearea.getLastStepVehicleNumber("area_north_approach_0_350")
    south_count = traci.lanearea.getLastStepVehicleNumber("area_south_approach_0_350")
    east_count = traci.lanearea.getLastStepVehicleNumber("area_east_approach_0_350")
    west_count = traci.lanearea.getLastStepVehicleNumber("area_west_approach_0_350")
    
    return north_count, south_count, east_count, west_count

def set_polygon_color_based_on_count(polygon_id, count):
    """Sets the color of a polygon based on vehicle count."""
    if count == 0:  # Green for 0 vehicles
        color = (0, 255, 0, 255)  # Green
    elif 1 <= count <= 5:  # Yellow for 1-5 vehicles
        color = (255, 255, 0, 255)  # Yellow
    else:  # count > 5 (Red state remains > 5 vehicles)
        color = (255, 0, 0, 255)  # Red
    try:
        traci.polygon.setColor(polygon_id, color)
    except traci.TraCIException as e:
        print(f"Edge: Error setting color for {polygon_id}: {e}")

def control_traffic_light(north_count, south_count, east_count, west_count, current_phase_index):
    global approach_red_durations

    detector_counts = {
        "north": north_count, "south": south_count,
        "east": east_count, "west": west_count
    }
    is_red_state = {}

    for approach, count in detector_counts.items():
        is_red_state[approach] = count > 5  # Changed threshold: Detector is 'red' if more than 5 vehicles
        if is_red_state[approach]:
            approach_red_durations[approach] += 1
        else:
            approach_red_durations[approach] = 0

    red_approach_candidates = []
    for approach_name in ["north", "south", "east", "west"]:
        if is_red_state[approach_name]:
            red_approach_candidates.append((approach_name, approach_red_durations[approach_name]))

    next_phase_to_set = current_phase_index
    priority_order = {"north": 0, "east": 1, "south": 2, "west": 3} # N > E > S > W

    # 1. Check for approaches red for > 5 steps (highest priority)
    long_red_candidates = []
    for approach_name in ["north", "south", "east", "west"]:
        if approach_red_durations[approach_name] > 5:
            long_red_candidates.append((approach_name, approach_red_durations[approach_name]))
    
    if long_red_candidates:
        long_red_candidates.sort(key=lambda x: (-x[1], priority_order[x[0]]))
        prioritized_approach_name = long_red_candidates[0][0]
        if prioritized_approach_name in ["north", "south"]:
            next_phase_to_set = 0  # N-S green
        else:  # east or west
            next_phase_to_set = 2  # E-W green
    # 2. If no approach is red > 5 steps, check for any red approaches (previous logic)
    elif red_approach_candidates:
        red_approach_candidates.sort(key=lambda x: (-x[1], priority_order[x[0]]))
        prioritized_approach_name = red_approach_candidates[0][0]
        if prioritized_approach_name in ["north", "south"]:
            next_phase_to_set = 0  # N-S green
        else:  # east or west
            next_phase_to_set = 2  # E-W green
    # 3. Fallback: No approaches are 'red' at all, use max vehicle count logic
    else:
        max_vehicles_ns = max(north_count, south_count)
        max_vehicles_ew = max(east_count, west_count)

        if max_vehicles_ns > max_vehicles_ew:
            next_phase_to_set = 0
        elif max_vehicles_ew > max_vehicles_ns:
            next_phase_to_set = 2
        else:  # Equal vehicles or all zero
            if north_count == 0 and south_count == 0 and east_count == 0 and west_count == 0:
                next_phase_to_set = 0  # Default to N-S green if no traffic
            else:
                next_phase_to_set = current_phase_index # Maintain current phase if balanced

    if next_phase_to_set != current_phase_index:
        try:
            traci.trafficlight.setPhase("center", next_phase_to_set)
        except traci.TraCIException as e:
            print(f"Edge: Error setting TLS phase for center: {e}")
        return next_phase_to_set
    
    return current_phase_index

# ————————————————
# 5) Main TraCI loop
# ————————————————
def run_edge():
    # 1) Start SUMO via TraCI
    sumo_cmd = [SUMO_BINARY, "-c", SUMO_CONFIG]
    traci.start(sumo_cmd, label="edge_sim")
    print("Edge: SUMO started, stepping through simulation...")

    # Initialize traffic light state
    current_phase_value = 0  # Start with N-S green (Phase 0)
    try:
        traci.trafficlight.setPhase("center", current_phase_value)
        print(f"Edge: Initial TLS phase set to {current_phase_value} for center")
    except traci.TraCIException as e:
        print(f"Edge: Error setting initial TLS phase for center: {e}")

    # Diagnostic: Check loaded polygon IDs
    try:
        all_polygon_ids = traci.polygon.getIDList()
        print(f"Edge: Loaded polygon IDs: {all_polygon_ids}")
        expected_polygons = ["poly_north_approach_strip", "poly_south_approach_strip", "poly_east_approach_strip", "poly_west_approach_strip"]
        for p_id in expected_polygons:
            if p_id not in all_polygon_ids:
                print(f"Edge: WARNING - Expected polygon '{p_id}' not found in loaded IDs!")
    except traci.TraCIException as e:
        print(f"Edge: Error getting polygon ID list: {e}")

    step = 0
    while traci.simulation.getMinExpectedNumber() > 0:
        traci.simulationStep()
        step += 1

        # Get sensor counts
        north_count, south_count, east_count, west_count = get_sensor_counts()
        
        # Control traffic light based on new logic
        current_phase_value = control_traffic_light(north_count, south_count, east_count, west_count, current_phase_value)

        # Prepare data for encryption
        report = {
            "timestep": step,
            "north_count": north_count,
            "south_count": south_count,
            "east_count": east_count,
            "west_count": west_count,
            "current_phase": current_phase_value
        }

        # Encrypt and send
        encrypted_msg = encrypt_report(report)
        sock.sendto(encrypted_msg, (UDP_IP, UDP_PORT))
        print(f"Edge [step {step}]: sent encrypted report → {report}")

        # Update detector colors
        set_polygon_color_based_on_count("poly_north_approach_strip", north_count)
        set_polygon_color_based_on_count("poly_south_approach_strip", south_count)
        set_polygon_color_based_on_count("poly_east_approach_strip", east_count)
        set_polygon_color_based_on_count("poly_west_approach_strip", west_count)

    traci.close()
    print("Edge: Simulation ended.")

if __name__ == "__main__":
    run_edge()