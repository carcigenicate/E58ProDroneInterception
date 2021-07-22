from collections import Callable

from scapy.packet import Packet

from e58pro.command_payloads import new_default_command_payload
from e58pro.shell_commands import produce_commands
from e58pro.transmitter_process import TransmitterProcessController

from interactive_shell.interactive_shell import InteractiveShell


DATAGRAMS_PER_SEND = 5


def interactive_shell_control_routine(proc_controller: TransmitterProcessController):
    """Starts a interactive shell to send commands to the drone."""
    try:
        shell = InteractiveShell(produce_commands(proc_controller, DATAGRAMS_PER_SEND))
        shell.loop()
    except KeyboardInterrupt:
        pass