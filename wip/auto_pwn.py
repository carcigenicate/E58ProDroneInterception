#!/usr/bin/env python3

from time import sleep
from typing import Callable

from scapy.layers.dot11 import RadioTap, Dot11FCS, Dot11QoS
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff
from threading import Thread, Event


DRONE_MAC = "18:b9:05:eb:16:ab"
DRONE_IP = "192.168.169.1"

TCP_DST_IP = "192.168.100.1"
TCP_START_SRC_PORT = 50000  # Arbitrary
TCP_DST_PORT = 18881

UDP_SRC_PORT = 34914  # Arbitrary. Will be where video is sent back?
UDP_DST_PORT = 8800

INTERFACE = "wlx4401bb9182b7"

# FIXME: Update with controller ap IP/MAC.
CONTROLLER_IP = "192.168.169.2"
CONTROLLER_MAC = "AC:22:0B:65:BB:50"


def produce_l2_data(src_mac: str, dst_mac: str, ap_mac: str):
    # TODO: Double check strings work for the types
    return RadioTap(present="Rate+TXFlags") / \
           Dot11FCS(addr1=dst_mac, addr2=src_mac, addr3=ap_mac, type="Data", subtype="QoS Data") / \
           Dot11QoS() / \
           LLC(ssap=0xAA, dsap=0xAA) / \
           SNAP()

def main_procedure(interface_name: str,
                   packet_validator: Callable[[Packet], bool],
                   ):
    pass