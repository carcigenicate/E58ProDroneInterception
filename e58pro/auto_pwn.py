#!/usr/bin/env python3

from typing import Optional

from scapy.arch import get_if_addr
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth, Dot11Beacon, Dot11Elt
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from scapy.config import conf

from scanners.channel_scanner import scan_channels
from scanners.interface_controller import InterfaceController
from e58pro.address_results import AddressResults
from e58pro.interception_routines import connectionless_interception_routine, connected_interception_routine

# DRONE_MAC = "18:b9:05:eb:16:ab"

WILDCARD_IP = "0.0.0.0"

DRONE_COMMAND_RECEIVE_PORT = 8800
DRONE_VIDEO_SEND_PORT = 1234

COMPLEX_SCANNER_BPF_FILTER = "(wlan type mgt) or udp"

SSID_ELEMENT_ID = 0


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
    For the SSID, only the prefix is checked. The entire strng doesn't need to match."""
    while True:
        last_channel = None
        beacon = None
        command = None
        video = None
        for chan, packet in scan_channels(interface_name, secs_per_channel, COMPLEX_SCANNER_BPF_FILTER):
            if last_channel != chan:
                if video or command or beacon:
                    return last_channel, beacon, command, video
                else:
                    beacon = None
                    command = None
                    video = None
                    last_channel = chan
            else:
                if Dot11Beacon in packet and _find_info_val_for(SSID_ELEMENT_ID, packet) == ssid_prefix:
                    ssid = _find_info_val_for(SSID_ELEMENT_ID, packet)
                    if ssid and ssid.startswith(ssid_prefix):
                        beacon = packet
                elif UDP in packet:
                    if packet[UDP].dport == command_receive_port:
                        command = packet
                    elif packet[UDP].sport == video_send_port:
                        video = packet


def connectionless_main(interface_name: str, secs_per_channel: float) -> None:
    inter_controller = InterfaceController(interface_name)
    inter_controller.set_monitor_mode(True)

    print("Scanning for drone...")
    channel, addrs = scan_for_drone(interface_name, secs_per_channel)
    print(f"Found: {addrs}")
    inter_controller.set_channel(channel)  # Should already be on the correct channel, but we'll set it for correctness.

    connectionless_interception_routine(interface_name, addrs)
    print("Exiting")


def connected_main(interface_name: str) -> None:
    # Accept BSSID and handle connection?
    try:
        our_ip = get_if_addr(interface_name)
        drone_ip = conf.route.route(WILDCARD_IP)[2]
        if drone_ip == WILDCARD_IP:
            raise RuntimeError("Unable to get default gateway. Are you connected?")
    except OSError as e:
        raise OSError(f"Cannot find device {interface_name}") from e

    connected_interception_routine(interface_name, drone_ip, our_ip)
