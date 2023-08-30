import pyshark
import matplotlib as plt

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

def traffic_per_phase_per_second(cap):
    protocol_volumes_per_phase = {}
    
    for phase_name, (start_time, end_time) in phases.items():
        print(phase_name)
        packets = [packet for packet in cap if start_time <= float(packet.frame_info.time_relative) <= end_time]

        if not packets:
            continue

        protocol_volumes = {}
        protocol_counts = {}
        duration = end_time - start_time

        for packet in packets:
            protocol = packet.highest_layer
            if protocol not in protocol_volumes:
                protocol_volumes[protocol] = 0
                protocol_counts[protocol] = 0
            protocol_volumes[protocol] += int(packet.length)
            protocol_counts[protocol] += 1

        mandatory_protocols = {"TCP", "UDP", "TLS", "DNS"}
        sorted_protocols = sorted(protocol_counts, key=protocol_counts.get, reverse=True)
        top_protocols = set(sorted_protocols[:5]) | mandatory_protocols

        for protocol in top_protocols:
            if protocol in protocol_volumes:
                if phase_name not in protocol_volumes_per_phase:
                    protocol_volumes_per_phase[phase_name] = {}
                protocol_volumes_per_phase[phase_name][protocol] = protocol_volumes[protocol] / duration
    
    for phase, protocol_data in protocol_volumes_per_phase.items():
        print(f"{phase}:")
        for protocol, volume in protocol_data.items():
            print(f"{protocol}: {volume:.2f} bytes/second")

traffic_per_phase_per_second(cap)

def volume_per_sec(cap):
    packets = [packet for packet in cap]

    max_time = float(packets[-1].frame_info.time_relative)

    sent_volume_per_second = [0] * (int(max_time) + 1)

    for packet in packets:
        if 'IP' in packet:
            timestamp = int(float(packet.frame_info.time_relative))
            sent_volume_per_second[timestamp] += int(packet.length)

    time = [i for i in range(len(sent_volume_per_second))]
    plt.plot(time, sent_volume_per_second, label="Data Volume")
    plt.xlabel('Time (seconds)')
    plt.ylabel('Volume (bytes)')
    plt.legend()
    plt.grid(True)

    plt.savefig('data_volume_plot.png')

    plt.close()

volume_per_sec(cap)


def volume_per_sec_per_protocol(cap):
    packets = [packet for packet in cap if float(packet.frame_info.time_relative) >= 40]

    if not packets:
        return

    max_time = float(packets[-1].frame_info.time_relative)

    protocol_volumes = {}
    protocol_counts = {}

    for packet in packets:
        protocol = packet.highest_layer
        timestamp = int(float(packet.frame_info.time_relative))
        if protocol not in protocol_volumes:
            protocol_volumes[protocol] = [0] * (int(max_time) + 1)
            protocol_counts[protocol] = 0
        protocol_volumes[protocol][timestamp] += int(packet.length)
        protocol_counts[protocol] += 1

    mandatory_protocols = {"TCP", "UDP", "TLS", "DNS"}
    sorted_protocols = sorted(protocol_counts, key=protocol_counts.get, reverse=True)
    top_protocols = set(sorted_protocols[:5]) | mandatory_protocols

    colors = ['#86C7D9', '#F9CDAE', '#B5EAD7', '#FFC3A0', '#C9CBCB', '#FFE5B4', '#E3AAD6', '#D9BF77', '#F49FBC', '#BEE3DB', '#F3D8E6', '#E2E6E6']

    plt.figure(figsize=(12, 6))

    time = [i for i in range(int(max_time) + 1)]
    for idx, protocol in enumerate(top_protocols):
        if protocol in protocol_volumes:
            plt.plot(time, protocol_volumes[protocol], label=f"{protocol} Data Volume", color=colors[idx % len(colors)])

    plt.xlabel('Time (seconds)')
    plt.ylabel('Volume (bytes)')
    plt.title('Data Volume per Second by Protocol')
    plt.legend()
    plt.grid(True)

    plt.savefig('data_volume_by_protocol_plot.png')

    plt.close()

volume_per_sec_per_protocol(cap)