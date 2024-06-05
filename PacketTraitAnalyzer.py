import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'pta'))

from pta.pcap_processor import extract_features_in_time_windows
from pta.csv_writer import write_to_csv

if len(sys.argv) != 3:
    print("Uso: python3 main.py <pcap_file> <output_file>")
    sys.exit(1)

pcap_file = sys.argv[1]
output_file = sys.argv[2]
window_size = 10  # seconds

features_in_windows = extract_features_in_time_windows(pcap_file, window_size)
write_to_csv(features_in_windows, output_file)
