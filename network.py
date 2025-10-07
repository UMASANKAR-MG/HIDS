import pyshark
from datetime import datetime
import pandas as pd
import os
import psutil

interface = psutil.net_if_addrs()
print("Available network interfaces:")
for iface in interface:
    print(f"- {iface}")
network_interface = input("Enter the network interface to capture packets: ")
    
def capture_packets():
    
    flow_data = {}
    packet_batch = []

    def get_flow_key(src_ip, src_port, dst_ip, dst_port):
        """Return a unique flow key and whether the packet is in forward direction."""
        forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        if forward_key in flow_data or reverse_key not in flow_data:
            return forward_key, True
        else:
            return reverse_key, False

    def initialize_flow(src_ip, src_port, dst_ip, dst_port, protocol, timestamp):
        """Initialize a new flow entry in flow_data."""
        flow_data[f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"] = {
            'src_ip': src_ip, 'src_port': src_port,
            'dst_ip': dst_ip, 'dst_port': dst_port,
            'protocol': protocol, 'start_time': timestamp,
            'end_time': timestamp, 'total_fwd_packets': 0,
            'total_bwd_packets': 0, 'total_length_fwd_packets': 0,
            'total_length_bwd_packets': 0, 'fwd_lengths': [],
            'bwd_lengths': [], 'fwd_timestamps': [],
            'bwd_timestamps': [], 'fwd_header_length': 0,
            'bwd_header_length': 0, 'psh_flags': 0,
            'syn_flags': 0, 'rst_flags': 0,
            'ack_flags': 0, 'fwd_urg_flags': 0,
            'bwd_urg_flags': 0
        }

    def parse_flag(flag):
        """Convert flag to int, default to 0 if non-numeric (e.g., 'True'/'False')."""
        try:
            return int(flag)
        except (ValueError, TypeError):
            return 0

    def update_flow_metrics(flow_key, packet, is_forward, timestamp, length):
        """Update metrics for each flow based on packet data."""
        flow = flow_data[flow_key]
        flow['end_time'] = timestamp

        if is_forward:
            flow['total_fwd_packets'] += 1
            flow['total_length_fwd_packets'] += length
            flow['fwd_lengths'].append(length)
            flow['fwd_timestamps'].append(timestamp)
            flow['fwd_header_length'] += int(packet.tcp.len) if hasattr(packet, 'tcp') else 0
        else:
            flow['total_bwd_packets'] += 1
            flow['total_length_bwd_packets'] += length
            flow['bwd_lengths'].append(length)
            flow['bwd_timestamps'].append(timestamp)
            flow['bwd_header_length'] += int(packet.tcp.len) if hasattr(packet, 'tcp') else 0

        if hasattr(packet, 'tcp'):
            if parse_flag(packet.tcp.flags_syn) == 1:
                flow['syn_flags'] += 1
            if parse_flag(packet.tcp.flags_push) == 1:
                flow['psh_flags'] += 1
            if parse_flag(packet.tcp.flags_reset) == 1:
                flow['rst_flags'] += 1
            if parse_flag(packet.tcp.flags_ack) == 1:
                flow['ack_flags'] += 1
            if parse_flag(packet.tcp.flags_urg) == 1:
                if is_forward:
                    flow['fwd_urg_flags'] += 1
                else:
                    flow['bwd_urg_flags'] += 1

    def append_to_csv(flow_stats, file_name='captured_traffic.csv'):
        if not os.path.isfile(file_name):
            pd.DataFrame(flow_stats).to_csv(file_name, index=False)
        else:
            pd.DataFrame(flow_stats).to_csv(file_name, mode='a', header=False, index=False)

    def calculate_metrics_for_flow(flow_key):
        """Calculate metrics for a specific flow."""
        flow = flow_data[flow_key]
        duration = (flow['end_time'] - flow['start_time']).total_seconds()
        fwd_packet_len_mean = sum(flow['fwd_lengths']) / len(flow['fwd_lengths']) if flow['fwd_lengths'] else 0
        bwd_packet_len_mean = sum(flow['bwd_lengths']) / len(flow['bwd_lengths']) if flow['bwd_lengths'] else 0
        fwd_iat_max = max([(flow['fwd_timestamps'][i] - flow['fwd_timestamps'][i - 1]).total_seconds() for i in range(1, len(flow['fwd_timestamps']))], default=0)
        bwd_iat_mean = sum([(flow['bwd_timestamps'][i] - flow['bwd_timestamps'][i - 1]).total_seconds() for i in range(1, len(flow['bwd_timestamps']))]) / len(flow['bwd_timestamps']) if len(flow['bwd_timestamps']) > 1 else 0
        min_packet_length = min(flow['fwd_lengths'] + flow['bwd_lengths']) if flow['fwd_lengths'] or flow['bwd_lengths'] else 0
        max_packet_length = max(flow['fwd_lengths'] + flow['bwd_lengths']) if flow['fwd_lengths'] or flow['bwd_lengths'] else 0

        return [{
            'Source IP': flow['src_ip'],
            'Source Port': flow['src_port'],
            'Destination IP': flow['dst_ip'],
            'Destination Port': flow['dst_port'],
            'Protocol': flow['protocol'],
            'Timestamp': flow['start_time'],
            'Flow Duration': duration,
            'Total Fwd Packets': flow['total_fwd_packets'],
            'Total Bwd Packets': flow['total_bwd_packets'],
            'Total Length of Fwd Packets': flow['total_length_fwd_packets'],
            'Total Length of Bwd Packets': flow['total_length_bwd_packets'],
            'Fwd Packet Length Mean': fwd_packet_len_mean,
            'Bwd Packet Length Mean': bwd_packet_len_mean,
            'Flow Packets/s': (flow['total_fwd_packets'] + flow['total_bwd_packets']) / duration if duration > 0 else 0,
            'Fwd IAT Max': fwd_iat_max,
            'Bwd IAT Mean': bwd_iat_mean,
            'Fwd Header Length': flow['fwd_header_length'],
            'Bwd Header Length': flow['bwd_header_length'],
            'Min Packet Length': min_packet_length,
            'Max Packet Length': max_packet_length,
            'FIN Flag Count': flow['rst_flags'], 
            'SYN Flag Count': flow['syn_flags'],
            'RST Flag Count': flow['rst_flags'],
            'PSH Flag Count': flow['psh_flags'],
            'ACK Flag Count': flow['ack_flags'],
            'URG Flag Count': flow['fwd_urg_flags'] + flow['bwd_urg_flags'],
        }]

    capture = pyshark.LiveCapture(interface=network_interface)
    print("Capturing packets... Press Ctrl+C to stop.")
    try:
        packet_count = 0
        for packet in capture.sniff_continuously():
            packet_count += 1
            if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.transport_layer
                timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))
                length = int(packet.length)
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport

                flow_key, is_forward = get_flow_key(src_ip, src_port, dst_ip, dst_port)

                if flow_key not in flow_data:
                    initialize_flow(src_ip, src_port, dst_ip, dst_port, protocol, timestamp)

                update_flow_metrics(flow_key, packet, is_forward, timestamp, length)
                flow_stats = calculate_metrics_for_flow(flow_key)
                packet_batch.extend(flow_stats)

            """if packet_count >= 1000:  # Stop capturing after 500 packets
                print(f"Captured {packet_count} packets, saving batch...")"""
            append_to_csv(packet_batch)
    except KeyboardInterrupt:
        print("Packet capture stopped.")
        append_to_csv(packet_batch)
    finally:
        capture.close()
capture_packets()

