#!/usr/bin/env python3

from time import sleep

from scapy.layers.dot11 import RadioTap, Dot11FCS, Dot11QoS
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import LLC, SNAP
from scapy.sendrecv import sendp
from threading import Thread, Event

from e58pro import E58ProHeader, E58ProSecondaryHeader
from interactive_shell import InteractiveShell
from commands import produce_commands

DRONE_MAC = "18:b9:05:eb:16:ab"
DRONE_IP = "192.168.169.1"

TCP_DST_IP = "192.168.100.1"
TCP_START_SRC_PORT = 50000  # Arbitrary
TCP_DST_PORT = 18881

UDP_SRC_PORT = 34914  # Arbitrary. Will be where video is sent back?
UDP_DST_PORT = 8800

INTERFACE = "wlx4401bb9182b7"

# FIXME: Update with controller ap IP/MAC.
OUR_IP = "192.168.169.2"
OUR_MAC = DRONE_MAC


L2_BASE = RadioTap(present="Rate+TXFlags") / \
          Dot11FCS(addr1=DRONE_MAC, addr2=OUR_MAC, addr3=DRONE_MAC, type=2, subtype=8) / \
          Dot11QoS() / \
          LLC(ssap=0xAA, dsap=0xAA) / \
          SNAP()

TCP_PING_BASE = L2_BASE / \
                IP(src=OUR_IP, dst=TCP_DST_IP) / \
                TCP(sport=TCP_START_SRC_PORT, dport=TCP_DST_PORT)

COMMAND_UDP_BASE = L2_BASE / \
                   IP(src=OUR_IP, dst=DRONE_IP) / \
                   UDP(sport=UDP_SRC_PORT, dport=UDP_DST_PORT)


def start_tcp_pinger(is_terminating: Event) -> None:
    def pinger():
        ping = TCP_PING_BASE.copy()
        while not is_terminating.is_set():
            sendp(ping, iface=INTERFACE, verbose=False)
            ping[TCP].sport += 1
            ping[TCP].seq += 1
            sleep(0.4)

    thread = Thread(target=pinger)
    thread.start()


def main():
    four_byte_packet = COMMAND_UDP_BASE / E58ProHeader()
    six_byte_packet = four_byte_packet / E58ProSecondaryHeader()

    terminating_event = Event()
    start_tcp_pinger(terminating_event)

    try:
        sendp(four_byte_packet * 5, iface=INTERFACE, verbose=False)
        sendp(six_byte_packet * 5, iface=INTERFACE, verbose=False)

        shell = InteractiveShell(produce_commands(INTERFACE, six_byte_packet))
        shell.loop()
    except KeyboardInterrupt:
        pass
    except PermissionError:
        raise PermissionError("Must be run as root!")
    finally:
        terminating_event.set()


main()
