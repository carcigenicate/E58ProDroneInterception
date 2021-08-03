import logging

from e58pro.command_payloads import Command
from e58pro.transmitter_process import TransmitterProcessController

DEFAULT_N_DATAGRAMS_PER_SEND = 10


class E58ProController:
    """A class that allows for control of an E58Pro (or equivalent) drone.
    sender_func should be either of scapy's send/sendp, or an equivalent function."""
    DEFAULT_KWARGS = {"verbose": False}

    def __init__(self,
                 proc_controller: TransmitterProcessController,
                 datagrams_per_send: int = DEFAULT_N_DATAGRAMS_PER_SEND):
        self._process_controller = proc_controller

        self._datagrams_per_send = datagrams_per_send

    def _send(self, should_persist: bool, /,  **fields):
        succeeded = self._process_controller.send_request(fields, self._datagrams_per_send, should_persist)
        if not succeeded:
            logging.warning(f"Failed to send due to full queue: {fields}")

    def takeoff(self) -> None:
        self._send(False, command=Command.TAKEOFF)

    def stop(self) -> None:
        self._send(False, command=Command.STOP)

    def gyro_check(self) -> None:
        self._send(False, command=Command.GYRO_CHECK)

    def elevation_control(self, value: int) -> None:
        """Ascending/descending. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send(True, left_vert=value)

    def turn_control(self, value: int) -> None:
        """Left/Right spin. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send(True, left_horz=value)

    def direction_control(self, value: int) -> None:
        """Forwards/backwards. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send(True, right_vert=value)

    def sideways_control(self, value: int) -> None:
        """Left/Right movement (not turning). Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send(True, right_horz=value)