import glob
from datetime import datetime

import numpy as np
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

import sniffer


class DNNDataset(object):
    def __init__(self):
        self.dataset_path = None
        self.dataset_label = None
        self.dnn_packet_list = []
        self.pps_list = []
        self.__pps_counter = 0
        self.__last_capture_second = -1
        self.lost_packets = 0
        self.locked = False

    def from_file(self, dataset_path=None, dataset_label=None):
        if dataset_path is None or dataset_label is None:
            return

        self.dataset_path = dataset_path
        self.dataset_label = dataset_label

        try:
            print("Reading", self.dataset_path)
            sniffer.read_capture(self.dataset_path, self.packet_callback)
            self.update_pps()
            print("Reading {} complete".format(self.dataset_path))
            print("Lost packets: {}\n".format(self.lost_packets))
        except Exception:
            raise Exception("Cannot read", self.dataset_path)

    def from_local_network(self, dataset_label, packet_count=0, capture_timeout=None):
        self.dataset_label = dataset_label
        sniffer.start_capture(packet_callback=self.packet_callback,
                              packet_count=packet_count,
                              capture_timeout=capture_timeout)
        self.update_pps()

    def from_folder(self, folder="", dataset_label=None):
        if dataset_label is None:
            return

        ddos_files = glob.glob(folder + "*.pcap")

        for file in ddos_files:
            self.from_file(file, dataset_label)

    def packet_callback(self, packet):
        if self.locked:
            return

        dnn_packet = DNNPacket()
        try:
            dnn_packet.parse(packet)
            dnn_packet.label = self.dataset_label.value
        except Exception:
            self.lost_packets += 1

        if dnn_packet is not None:
            self.calc_pps(packet)
            self.dnn_packet_list.append(dnn_packet)
        else:
            print("Packet callback: packet is None")

    def update_pps(self):
        for second, pps in self.pps_list:
            for packet in self.dnn_packet_list:
                packet_sec = datetime.fromtimestamp(packet.timestamp).second
                if packet_sec == second and packet.pps == -1:
                    packet.pps = pps

        self.pps_list.clear()

    def calc_pps(self, packet):
        capture_second = datetime.fromtimestamp(packet.time).second

        if self.__last_capture_second == -1:
            self.__pps_counter += 1
            self.__last_capture_second = capture_second

        elif self.__last_capture_second == capture_second:
            self.__pps_counter += 1

        else:
            self.pps_list.append((self.__last_capture_second, self.__pps_counter))
            self.__last_capture_second = capture_second
            self.__pps_counter = 0

    def to_numpy(self, split_for_training=False):
        packet_values = [list(p.dict.values()) for p in self.dnn_packet_list]

        numpy_dataset = np.array(packet_values, dtype=np.float)
        train_dataset_size = int(numpy_dataset.shape[0] * 0.8)

        if split_for_training:
            return (numpy_dataset[:train_dataset_size],
                    np.array([self.dnn_packet_list[i].label for i in range(train_dataset_size)]),
                    numpy_dataset[train_dataset_size:],
                    np.array(
                        [self.dnn_packet_list[i].label for i in range(train_dataset_size, numpy_dataset.shape[0])]))
        else:
            return numpy_dataset, np.array([p.label for p in self.dnn_packet_list])

    @property
    def length(self):
        return len(self.dnn_packet_list)

    @staticmethod
    def cross(dataset1, dataset2):
        import random

        cross_dataset = DNNDataset()
        for packet1, packet2 in zip(dataset1.dnn_packet_list, dataset2.dnn_packet_list):
            cross_dataset.dnn_packet_list.append(packet1)
            cross_dataset.dnn_packet_list.append(packet2)

        random.shuffle(cross_dataset.dnn_packet_list)

        return cross_dataset


class DNNPacket(object):
    def __init__(self, label=0):
        self.label = label
        self.hop_limit = -1
        self.next_header = -1
        self.length = -1
        self.pps = -1

        self.timestamp = -1

    def parse(self, packet):
        self.timestamp = packet.time
        self.length = len(packet)

        if IP in packet:
            self.from_ipv4(packet[IP])
        elif IPv6 in packet:
            self.from_ipv6(packet[IPv6])
        else:
            raise Exception("Cannot parse packet")

    def from_ipv4(self, packet_header):
        self.hop_limit = packet_header.ttl
        self.next_header = packet_header.proto

    def from_ipv6(self, packet_header):
        self.hop_limit = packet_header.hlim
        self.next_header = packet_header.nh

    @property
    def dict(self):
        custom_dict = self.__dict__.copy()
        custom_dict.pop("label")
        custom_dict.pop("timestamp")
        return custom_dict
