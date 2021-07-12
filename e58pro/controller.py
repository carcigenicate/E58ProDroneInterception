from typing import Any

from scapy.sendrecv import sendp
from scapy.layers.inet import UDP

from e58pro.command_payloads import E58ProBasePayload, new_default_command_payload, Command

# FIXME: Completely untested
# TODO: Change the shell to use this class instead of the closures it's using now?

class E58ProController:
    """A class that allows for control of an E58Pro (or equivalent) drone."""
    DEFAULT_KWARGS = {"verbose": False}

    def __init__(self, interface_name: str, l4_base: UDP, **scapy_sendp_kwargs):
        self._iface: str = interface_name
        self._l4_base: UDP = l4_base
        self._send_kwargs: dict[str, Any] = E58ProController.DEFAULT_KWARGS | scapy_sendp_kwargs

        self._command: E58ProBasePayload = new_default_command_payload()

    def _send(self, **fields) -> None:
        for field_name, field_val in fields.items():
            setattr(self._command, field_name, field_val)
        sendp(self._l4_base / self._command, iface=self._iface, **self._send_kwargs)

    def takeoff(self) -> None:
        self._send(command=Command.TAKEOFF)

    # They're the same command.
    land = takeoff

    def stop(self) -> None:
        self._send(command=Command.STOP)

    def roll(self) -> None:
        self._send(command=Command.ROLL)

    def gyro_check(self) -> None:
        self._send(command=Command.GYRO_CHECK)

    def elevation_control(self, value: int) -> None:
        """Ascending/descending. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send(left_vert=value)

    def turn_control(self, value: int) -> None:
        """Left/Right spin. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send(left_horz=value)

    def direction_control(self, value: int) -> None:
        """Forwards/backwards. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send(right_vert=value)

    def sideways_control(self, value: int) -> None:
        """Left/Right movement (not turning). Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send(right_horz=value)

    def reset(self) -> None:
        """Resets the internal command state to neutral fields. Should not be necessary."""
        self._command = new_default_command_payload()