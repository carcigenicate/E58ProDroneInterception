from scapy.packet import Packet
from scapy.sendrecv import sendp

from e58pro import E58ProBasePayload, Command
from command_shell import mapping_from_named_functions, CommandMapping



def produce_commands(interface_name: str, packet_base: Packet) -> CommandMapping:
    def _send(payload):
        sendp(packet_base / payload, iface=interface_name, verbose=False)

    def takeoff():
        """Initiates takeoff."""
        _send(E58ProBasePayload(command=Command.TAKEOFF))

    def stop():
        """Kills the motors for safety."""
        _send(E58ProBasePayload(command=Command.STOP))

    def man(*pairs):
        """man(ually) set attributes of the packet. Available attributes are:\n"""
        if len(pairs) & 1:
            return "Must supply an even number of arguments."
        else:
            payload = E58ProBasePayload()
            it = iter(pairs)
            for attr in it:
                val = int(next(it))
                print(f"Pair: {attr}, {val}")
                setattr(payload, attr, val)
            _send(payload)

    man.__doc__ += ", ".join(field.name for field in E58ProBasePayload.fields_desc)

    return mapping_from_named_functions([takeoff, stop, man])