import pyshark
from collections import Counter

filename = 'full.pcapng'
cap = pyshark.FileCapture(filename)

phases = {
    "Open": (9, 38),
    "Send and receiving messages": (38, 79),
    "Starting audio call": (79, 124),
    "Starting video call with both users having the video": (124, 165),
    "Starting video call with one user having the video": (165, 192),
    "Ending call": (192, 215),
    "Closing app": (215, 400)
}

phase_stats = {}
for phase in phases:
    phase_stats[phase] = {
        "TCP": 0,
        "UDP": 0
    }

for packet in cap:
    if hasattr(packet, 'frame_info'):  # ensure it has frame_info
        time_relative = float(packet.frame_info.time_relative)
        
        transport_layer = packet.transport_layer
        
        for phase, (start, end) in phases.items():
            if start <= time_relative <= end:
                if transport_layer == "TCP":
                    phase_stats[phase]["TCP"] += 1
                elif transport_layer == "UDP":
                    phase_stats[phase]["UDP"] += 1
                break  # exit the loop once we've found the phase

for phase, stats in phase_stats.items():
    print(f"{phase}:")
    print(f"TCP packets: {stats['TCP']}")
    print(f"UDP packets: {stats['UDP']}")


protocol_counter = Counter()

for packet in cap:
    if 'UDP' in packet:
        highest_layer = packet.highest_layer
        if highest_layer not in ['UDP', 'QUIC', 'DNS']:
            protocol_counter[highest_layer] += 1

for protocol, count in protocol_counter.items():
    print(f'{protocol}: {count}')

data = {
    "Open": {"TCP": 4801, "UDP": 180},
    "Send and receiving messages": {"TCP": 933, "UDP": 21},
    "Starting audio call": {"TCP": 510, "UDP": 646},
    "Starting video call with both users having the video": {"TCP": 130, "UDP": 7198},
    "Starting video call with one user having the video": {"TCP": 80, "UDP": 3354},
    "Ending call": {"TCP": 181, "UDP": 183},
    "Closing app": {"TCP": 111, "UDP": 11}
}

result = {}

for phase, (start, end) in phases.items():
    time_interval = end - start
    result[phase] = {
        "TCP": data[phase]["TCP"] / time_interval,
        "UDP": data[phase]["UDP"] / time_interval
    }

for phase, values in result.items():
    print(f"{phase}:\nTCP packets per second: {values['TCP']:.2f}\nUDP packets per second: {values['UDP']:.2f}\n")
