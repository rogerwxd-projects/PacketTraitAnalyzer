## PacketTrait Analyzer

Packet Trait Analyzer is a tool to extracts network features from pcap files in specified time windows and writes the aggregated features to a CSV file.

Purpose
The aim of this tool is to calculate network flow statistics from a given capture file (PCAP). PacketTrait Analyzer has been designed with offline processing as its main focus.

### Installation

```bash
pip install -r requirements.txt
```

### Usage
The current usage of the program is not documented due to rapid changes in the program's functionality in its early stages. However, if you run the PacketTrait Analyzer, the currently implemented options should be displayed. A typical use case might be something like:

```python
python3 PacketTrait_Analyzer.py data_pcap/example.pcap data_csv/example.csv
```

### Features extracted

```bash
    StartTime NUMERIC
    EndTime NUMERIC
    SourceIP NUMERIC
    DestinationIP NUMERIC
    SourcePort NUMERIC
    DestinationPort NUMERIC
    Protocol STRING
    Flags STRING
    TotalPacketSize NUMERIC
    PacketSizeMin NUMERIC
    PacketSizeMax NUMERIC
    PacketSizeMean NUMERIC
    PacketSizeStdDev NUMERIC
    PayloadSize NUMERIC
    PayloadSizeMin NUMERIC
    PayloadSizeMax NUMERIC
    PayloadSizeMean NUMERIC
    PayloadSizeStdDev NUMERIC
    TTLSize NUMERIC
    TTLSizeMin NUMERIC
    TTLSizeMax NUMERIC
    TTLSizeMean NUMERIC
    TTLSizeStdDev NUMERIC
    HeaderSize NUMERIC
    HeaderSizeMin NUMERIC
    HeaderSizeMax NUMERIC
    HeaderSizeMean NUMERIC
    HeaderSizeStdDev NUMERIC
    ChksumSize NUMERIC
    ChksumSizeMin NUMERIC
    ChksumSizeMax NUMERIC
    ChksumSizeMean NUMERIC
    ChksumSizeStdDev NUMERIC
```