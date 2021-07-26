from e58pro.transmitter_process import TransmitterProcessController
from e58pro.controller import E58ProController

from interactive_shell.interactive_shell import mapping_from_named_functions, CommandMapping


def produce_commands(proc_controller: TransmitterProcessController,
                     datagrams_per_send: int) -> CommandMapping:
    controller = E58ProController(proc_controller, datagrams_per_send)

    def takeoff():
        """Initiates takeoff."""
        controller.takeoff()

    def stop():
        """Kills the motors for safety."""
        return controller.stop()

    return mapping_from_named_functions([takeoff, stop])