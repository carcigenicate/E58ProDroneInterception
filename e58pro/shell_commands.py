from typing import Sequence

from e58pro.command_payloads import E58ProBasePayload, Command
from interactive_shell.interactive_shell import mapping_from_named_functions, CommandMapping
from e58pro.transmitter_process import TransmitterProcessController, CommandRequest

HELP_CHUNK_SIZE = 5


def _chunk(seq: Sequence, chunk_size: int):
    for i in range(0, len(seq), chunk_size):
        yield seq[i:i+chunk_size]


# TODO: Add "sender_func" parameter so can be used in connected mode.
def produce_commands(proc_controller: TransmitterProcessController,
                     datagrams_per_send: int) -> CommandMapping:
    def _q(**fields):
        proc_controller.send_request(fields, datagrams_per_send)

    def takeoff():
        """Initiates takeoff."""
        return _q(command=Command.TAKEOFF)

    def stop():
        """Kills the motors for safety."""
        return _q(command=Command.STOP)

    # def set(*pairs):
    #     """Set attributes of the packet. Available attributes are:\n"""
    #     if len(pairs) & 1:
    #         return "Must supply an even number of arguments."
    #     else:
    #         pack_copy = command_packet.copy()
    #         payload = pack_copy[E58ProBasePayload]
    #         it = iter(pairs)
    #         for attr in it:
    #             val = int(next(it))
    #             setattr(payload, attr, val)
    #         return _q(pack_copy)

    #names = [field.name for field in E58ProBasePayload.fields_desc]
    #set.__doc__ += ",\n".join(", ".join(chunk) for chunk in _chunk(names, HELP_CHUNK_SIZE))

    return mapping_from_named_functions([takeoff, stop])