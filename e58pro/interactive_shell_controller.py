from e58pro.shell_commands import produce_commands
from e58pro.transmitter_process import TransmitterProcessController

from interactive_shell.interactive_shell import InteractiveShell


DATAGRAMS_PER_SEND = 5


def interactive_shell_control_routine(proc_controller: TransmitterProcessController):
    """Starts a interactive shell to send commands to the drone."""
    try:
        commands = produce_commands(proc_controller, DATAGRAMS_PER_SEND)
        shell = InteractiveShell(commands)
        shell.loop()
    except KeyboardInterrupt:
        pass
