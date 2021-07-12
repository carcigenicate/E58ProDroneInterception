from typing import Optional, Iterator

from scapy.packet import Packet
from scapy.sendrecv import sniff

from scanners.interface_controller import InterfaceController

# Address 1 is the receiver, Address 2 is the transmitter, Address 3 is used for filtering purposes by the receiver.


def scan_channels(interface_name: str,
                  secs_per_channel: float,
                  bpf_filter: Optional[str] = None
                  ) -> Iterator[tuple[int, Packet]]:
    """Listens on interface_name, for secs_per_channel seconds per channel.
    A BPF filter can be supplied to filter the incoming packets.
    Returns a iterator of tuples of (channel, packet) for every packet sniffed."""
    controller = InterfaceController(interface_name)
    for chan in controller.get_supported_channels():
        controller.set_channel(chan)
        for packet in sniff(iface=interface_name, timeout=secs_per_channel, filter=bpf_filter):
            yield chan, packet


# def _is_unicast(mac: str) -> bool:
#     # FIXME: Bad and inefficient. A MAC is unicast if the LSB of the first octet (index 1 in the string) is even.
#     # int should be safe to use here since the second character of a MAC will always be a hex value.
#     return not (int(mac[1], 16) & 1)
#
#
# def find_stations_connected_to(interface_name: str, ap_mac: str, scan_duration: float) -> set[str]:
#     """Returns the MAC addresses of stations that are found to be connected to the given AP."""
#     sniffed = sniff(iface=interface_name, timeout=scan_duration)
#     from_to_ap = [p
#                   for p in sniffed
#                   # If either MAC is the AP (sort out which is which in the next step)
#                   # TODO: Check for both IP and Dot11?
#                   if IP in p and (p[Dot11].addr1 == ap_mac or p[Dot11].addr2 == ap_mac)]
#     station_macs = {p[Dot11].addr1 if p[Dot11].addr2 == ap_mac else p[Dot11].addr2
#                     for p in from_to_ap}
#     return {mac for mac in station_macs if _is_unicast(mac)}


# def sniff_for_beacon(interface_name: str, target_ssid_prefix: bytes) -> Optional[Dot11Beacon]:
#     def filter_func(p: Packet):
#         if Dot11Beacon in p:
#             ssid = _find_info_val_for(SSID_ELEMENT_ID, p)
#             if ssid and ssid.startswith(target_ssid_prefix):
#                 return True
#         return False
#     wrapped_beacon = sniff(iface=interface_name, lfilter=filter_func, count=1)
#     return (wrapped_beacon and wrapped_beacon[0]) or None





