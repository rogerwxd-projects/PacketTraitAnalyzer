from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import statistics

def extract_features_in_time_windows(pcap_file, window_size):
    """
    Extract network features within specified time windows from a pcap file.

    Args:
        pcap_file (str): Path to the pcap file.
        window_size (int): Size of the time window in seconds.

    Returns:
        dict: Aggregated features by time window and IP pairs.
    """
    packets = rdpcap(pcap_file)
    start_time = packets[0].time
    end_time = packets[-1].time

    time_windows = [(float(t), float(t + window_size)) for t in range(int(start_time), int(end_time), window_size)]
    features_in_windows = defaultdict(lambda: defaultdict(list))

    for window_start, window_end in time_windows:
        for packet in packets:
            if window_start <= packet.time < window_end and IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ip_pair = (src_ip, dst_ip)

                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    protocol = "TCP"
                    flags = packet[TCP].flags
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    protocol = "UDP"
                    flags = "N/A"
                else:
                    src_port = "N/A"
                    dst_port = "N/A"
                    protocol = "Other"
                    flags = "N/A"

                packet_size = len(packet)
                payload_size = len(packet.payload)
                ttl_size = packet[IP].ttl
                header_size = packet[IP].ihl * 4
                chksum_size = packet[IP].chksum if isinstance(packet[IP].chksum, int) else 0

                features_in_windows[(window_start, window_end)][ip_pair].append({
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "flags": flags,
                    "packet_size": packet_size,
                    "payload_size": payload_size,
                    "ttl_size": ttl_size,
                    "header_size": header_size,
                    "chksum_size": chksum_size
                })

    aggregated_features = defaultdict(dict)

    for time_window, ip_data in features_in_windows.items():
        window_start, window_end = time_window
        for ip_pair, features in ip_data.items():
            src_ip, dst_ip = ip_pair
            src_ports = {f["src_port"] for f in features}
            dst_ports = {f["dst_port"] for f in features}
            protocols = {f["protocol"] for f in features}
            flags = {f["flags"] for f in features}
            packet_sizes = [f["packet_size"] for f in features]
            payload_sizes = [f["payload_size"] for f in features]
            ttl_sizes = [f["ttl_size"] for f in features]
            header_sizes = [f["header_size"] for f in features]
            chksum_sizes = [f["chksum_size"] for f in features]

            aggregated_features[(window_start, window_end)][ip_pair] = {
                "src_port": src_ports,
                "dst_port": dst_ports,
                "protocol": protocols,
                "flags": flags,
                "packet_size": sum(packet_sizes),
                "packet_size_min": min(packet_sizes),
                "packet_size_max": max(packet_sizes),
                "packet_size_mean": statistics.mean(packet_sizes),
                "packet_size_std_deviation": statistics.stdev(packet_sizes) if len(packet_sizes) > 1 else 0,
                "payload_size": sum(payload_sizes),
                "payload_size_min": min(payload_sizes),
                "payload_size_max": max(payload_sizes),
                "payload_size_mean": statistics.mean(payload_sizes),
                "payload_size_std_deviation": statistics.stdev(payload_sizes) if len(payload_sizes) > 1 else 0,
                "ttl_size": sum(ttl_sizes),
                "ttl_size_min": min(ttl_sizes),
                "ttl_size_max": max(ttl_sizes),
                "ttl_size_mean": statistics.mean(ttl_sizes),
                "ttl_size_std_deviation": statistics.stdev(ttl_sizes) if len(ttl_sizes) > 1 else 0,
                "header_size": sum(header_sizes),
                "header_size_min": min(header_sizes),
                "header_size_max": max(header_sizes),
                "header_size_mean": statistics.mean(header_sizes),
                "header_size_std_deviation": statistics.stdev(header_sizes) if len(header_sizes) > 1 else 0,
                "chksum_size": sum(chksum_sizes),
                "chksum_size_min": min(chksum_sizes),
                "chksum_size_max": max(chksum_sizes),
                "chksum_size_mean": statistics.mean(chksum_sizes),
                "chksum_size_std_deviation": statistics.stdev(chksum_sizes) if len(chksum_sizes) > 1 else 0
            }

    return aggregated_features
