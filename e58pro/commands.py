from typing import Sequence, Type
from time import sleep

from scapy.packet import Packet
from scapy.sendrecv import sendp

from e58pro.packet_structures import E58ProBasePayload, Command
from interactive_shell.interactive_shell import mapping_from_named_functions, CommandMapping

HELP_CHUNK_SIZE = 5


def _chunk(seq: Sequence, chunk_size: int):
    for i in range(0, len(seq), chunk_size):
        yield seq[i:i+chunk_size]


def produce_commands(interface_name: str, command_packet: E58ProBasePayload) -> CommandMapping:
    def _send(packet: Packet):
        sendp(packet, iface=interface_name, verbose=False)

    def _mod_copy(layer: Type[Packet], field: str, value) -> Packet:
        copy = command_packet.copy()
        setattr(copy[layer], field, value)
        return copy

    takeoff_packet = _mod_copy(E58ProBasePayload, "command", Command.TAKEOFF)

    def takeoff():
        """Initiates takeoff."""
        return _send(takeoff_packet)

    def stop():
        """Kills the motors for safety."""
        return _send(_mod_copy(E58ProBasePayload, "command", Command.STOP))

    def cycle(n: float = 5, t: float = 1):
        """Take of and land n times with a delay of t seconds."""
        for _ in range(int(n)):
            _send(takeoff_packet)
            sleep(t)

    def set(*pairs):
        """Set attributes of the packet. Available attributes are:\n"""
        if len(pairs) & 1:
            return "Must supply an even number of arguments."
        else:
            pack_copy = command_packet.copy()
            payload = pack_copy[E58ProBasePayload]
            it = iter(pairs)
            for attr in it:
                val = int(next(it))
                setattr(payload, attr, val)
            return _send(pack_copy)

    names = [field.name for field in E58ProBasePayload.fields_desc]
    set.__doc__ += ",\n".join(", ".join(chunk) for chunk in _chunk(names, HELP_CHUNK_SIZE))

    return mapping_from_named_functions([takeoff, stop, set, cycle])