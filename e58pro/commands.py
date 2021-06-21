from typing import Sequence
from time import sleep

from scapy.packet import Packet
from scapy.sendrecv import sendp

from e58pro.e58pro import E58ProBasePayload, Command
from interactive_shell.interactive_shell import mapping_from_named_functions, CommandMapping

HELP_CHUNK_SIZE = 5


def _chunk(seq: Sequence, chunk_size: int):
    for i in range(0, len(seq), chunk_size):
        yield seq[i:i+chunk_size]


def produce_commands(interface_name: str, packet_base: Packet) -> CommandMapping:
    def _send(payload):
        sendp(packet_base / payload, iface=interface_name, verbose=False)

    takeoff_payload = E58ProBasePayload(command=Command.TAKEOFF)

    def takeoff():
        """Initiates takeoff."""
        return _send(takeoff_payload)

    def stop():
        """Kills the motors for safety."""
        return _send(E58ProBasePayload(command=Command.STOP))

    def cycle(n: float = 5, t: float = 1):
        """Take of and land n times with a delay of t seconds."""
        for _ in range(int(n)):
            _send(takeoff_payload)
            sleep(t)

    def set(*pairs):
        """Set attributes of the packet. Available attributes are:\n"""
        if len(pairs) & 1:
            return "Must supply an even number of arguments."
        else:
            payload = E58ProBasePayload()
            it = iter(pairs)
            for attr in it:
                val = int(next(it))
                setattr(payload, attr, val)
            return _send(payload)

    names = [field.name for field in E58ProBasePayload.fields_desc]
    set.__doc__ += ",\n".join(", ".join(chunk) for chunk in _chunk(names, HELP_CHUNK_SIZE))

    return mapping_from_named_functions([takeoff, stop, set, cycle])