"""
@author: Adalberto Nassu Pompolo

"""

from scapy.all import sniff, PcapReader


def start_capture(packet_count=0, capture_timeout=None, packet_callback=None):
    sniff(count=packet_count, store=False, timeout=capture_timeout, prn=packet_callback)


def read_capture(capture_file, packet_callback=None):
    with PcapReader(capture_file) as reader:
        for packet in reader:
            packet_callback(packet)
