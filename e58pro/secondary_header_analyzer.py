#!/usr/bin/env python3

from time import sleep

from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srp1
from threading import Thread, Event

from e58pro import E58ProHeader, E58ProSecondaryHeader, E58ProBasePayload

DRONE_MAC = "18:b9:05:eb:16:ab"
DRONE_IP = "192.168.169.1"

UDP_SRC_PORT = 34914
UDP_DST_PORT = 8800

INTERFACE = "wlx4401bb9182b7"
try:
    OUR_IP = get_if_addr(INTERFACE)
    OUR_MAC = get_if_hwaddr(INTERFACE)
except OSError as e:
    raise OSError(f"Cannot find device {INTERFACE}") from e

COMMAND_UDP_BASE = Ether(src=OUR_MAC, dst=DRONE_MAC) / \
                   IP(src=OUR_IP, dst=DRONE_IP) / \
                   UDP(sport=UDP_SRC_PORT, dport=UDP_DST_PORT)


def main():
    packet = COMMAND_UDP_BASE / E58ProHeader() / E58ProSecondaryHeader()

    for payload in range(256):
        packet[E58ProSecondaryHeader].secondary_header_payload = payload
        response = srp1(packet, iface=INTERFACE, verbose=False)
        response.show()


main()