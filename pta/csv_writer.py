import csv

def write_to_csv(features_in_windows, output_file):
    """
    Write aggregated features to a CSV file.

    Args:
        features_in_windows (dict): Aggregated features by time window and IP pairs.
        output_file (str): Path to the output CSV file.
    """
    fieldnames = [
        "StartTime", "EndTime", "SourceIP", "DestinationIP", "SourcePort",
        "DestinationPort", "Protocol", "Flags", "TotalPacketSize", "PacketSizeMin",
        "PacketSizeMax", "PacketSizeMean", "PacketSizeStdDev", "PayloadSize",
        "PayloadSizeMin", "PayloadSizeMax", "PayloadSizeMean", "PayloadSizeStdDev",
        "TTLSize", "TTLSizeMin", "TTLSizeMax", "TTLSizeMean", "TTLSizeStdDev",
        "HeaderSize", "HeaderSizeMin", "HeaderSizeMax", "HeaderSizeMean", "HeaderSizeStdDev",
        "ChksumSize", "ChksumSizeMin", "ChksumSizeMax", "ChksumSizeMean", "ChksumSizeStdDev"
    ]

    with open(output_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for (window_start, window_end), ip_pair_features in features_in_windows.items():
            for ip_pair, features in ip_pair_features.items():
                src_ip, dst_ip = ip_pair
                writer.writerow({
                    "StartTime": window_start,
                    "EndTime": window_end,
                    "SourceIP": src_ip,
                    "DestinationIP": dst_ip,
                    "SourcePort": ".".join(str(port) for port in features["src_port"]),
                    "DestinationPort": ".".join(str(port) for port in features["dst_port"]),
                    "Protocol": ".".join(features["protocol"]),
                    "Flags": ".".join(str(flag) for flag in features["flags"]),
                    "TotalPacketSize": features["packet_size"],
                    "PacketSizeMin": features["packet_size_min"],
                    "PacketSizeMax": features["packet_size_max"],
                    "PacketSizeMean": features["packet_size_mean"],
                    "PacketSizeStdDev": features["packet_size_std_deviation"],
                    "PayloadSize": features["payload_size"],
                    "PayloadSizeMin": features["payload_size_min"],
                    "PayloadSizeMax": features["payload_size_max"],
                    "PayloadSizeMean": features["payload_size_mean"],
                    "PayloadSizeStdDev": features["payload_size_std_deviation"],
                    "TTLSize": features["ttl_size"],
                    "TTLSizeMin": features["ttl_size_min"],
                    "TTLSizeMax": features["ttl_size_max"],
                    "TTLSizeMean": features["ttl_size_mean"],
                    "TTLSizeStdDev": features["ttl_size_std_deviation"],
                    "HeaderSize": features["header_size"],
                    "HeaderSizeMin": features["header_size_min"],
                    "HeaderSizeMax": features["header_size_max"],
                    "HeaderSizeMean": features["header_size_mean"],
                    "HeaderSizeStdDev": features["header_size_std_deviation"],
                    "ChksumSize": features["chksum_size"],
                    "ChksumSizeMin": features["chksum_size_min"],
                    "ChksumSizeMax": features["chksum_size_max"],
                    "ChksumSizeMean": features["chksum_size_mean"],
                    "ChksumSizeStdDev": features["chksum_size_std_deviation"]
                })
