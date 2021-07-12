from collections import Callable

from scapy.packet import Packet

from e58pro.command_payloads import new_default_command_payload
from e58pro.interception_routines import keep_alive_initialization
from e58pro.shell_commands import produce_commands

from interactive_shell.interactive_shell import InteractiveShell


def interactive_shell_control_routine(interface_name: str, l4_base: Packet, sender_func: Callable):
    """Starts a interactive shell to send commands to the drone."""
    keep_alive_termination_event = keep_alive_initialization(interface_name, l4_base, sender_func)

    command_packet = l4_base / new_default_command_payload()
    try:
        shell = InteractiveShell(produce_commands(interface_name, command_packet, sender_func))
        shell.loop()
    except KeyboardInterrupt:
        pass
    finally:
        keep_alive_termination_event.set()