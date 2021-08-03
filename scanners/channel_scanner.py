from typing import Optional, Iterator

from scapy.packet import Packet
from scapy.sendrecv import sniff

from scanners.interface_controller import InterfaceController


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




