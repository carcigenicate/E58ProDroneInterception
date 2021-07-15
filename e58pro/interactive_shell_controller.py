from collections import Callable

from scapy.packet import Packet

from e58pro.command_payloads import new_default_command_payload
from e58pro.shell_commands import produce_commands

from interactive_shell.interactive_shell import InteractiveShell


DATAGRAMS_PER_SEND = 5


def interactive_shell_control_routine(interface_name: str, l4_base: Packet, sender_func: Callable):
    """Starts a interactive shell to send commands to the drone."""
    command_packet = l4_base / new_default_command_payload()
    try:
        shell = InteractiveShell(produce_commands(interface_name, command_packet, sender_func, DATAGRAMS_PER_SEND))
        shell.loop()
    except KeyboardInterrupt:
        pass