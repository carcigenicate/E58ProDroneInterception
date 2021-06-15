#!/usr/bin/env python3

from time import sleep

from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from threading import Thread, Event

from e58pro import E58ProHeader, E58ProSecondaryHeader
from command_shell import CommandShell
from commands import produce_commands

DRONE_MAC = "18:b9:05:eb:16:ab"
DRONE_IP = "192.168.169.1"

TCP_DST_IP = "192.168.100.1"
TCP_START_SRC_PORT = 50000  # Arbitrary
TCP_DST_PORT = 18881

UDP_SRC_PORT = 34914  # Arbitrary. Will be where video is sent back?
UDP_DST_PORT = 8800

INTERFACE = "wlx4401bb9182b7"
try:
    OUR_IP = get_if_addr(INTERFACE)
    OUR_MAC = get_if_hwaddr(INTERFACE)
except OSError as e:
    raise OSError(f"Cannot find device {INTERFACE}") from e

TCP_PING_BASE = Ether(dst=DRONE_MAC) / \
                IP(src=OUR_IP, dst=TCP_DST_IP) / \
                TCP(sport=TCP_START_SRC_PORT, dport=TCP_DST_PORT)  # Add "options" to match drone traffic?

COMMAND_UDP_BASE = Ether(dst=DRONE_MAC) / \
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

        command_shell = CommandShell(produce_commands(INTERFACE, six_byte_packet))
        command_shell.command_loop()
    except KeyboardInterrupt:
        pass
    except PermissionError:
        raise PermissionError("Must be run as root!")
    finally:
        terminating_event.set()


main()
