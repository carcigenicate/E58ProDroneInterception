from typing import Any, Callable

from scapy.sendrecv import sendp
from scapy.layers.inet import UDP

from e58pro.command_payloads import E58ProBasePayload, new_default_command_payload, Command

# FIXME: Completely untested
# TODO: Change the shell to use this class instead of the closures it's using now?

DEFAULT_N_DATAGRAMS_PER_SEND = 10


class E58ProController:
    """A class that allows for control of an E58Pro (or equivalent) drone.
    sender_func should be either of scapy's send/sendp, or an equivalent function."""
    DEFAULT_KWARGS = {"verbose": False}

    def __init__(self,
                 interface_name: str,
                 l4_base: UDP,
                 sender_func: Callable,
                 datagrams_per_send: int = DEFAULT_N_DATAGRAMS_PER_SEND,
                 **scapy_sendp_kwargs):
        self._iface: str = interface_name
        self._l4_base: UDP = l4_base
        self._sender_func = sender_func

        self._datagrams_per_send = datagrams_per_send
        self._send_kwargs: dict[str, Any] = E58ProController.DEFAULT_KWARGS | scapy_sendp_kwargs

        self._persisted_command: E58ProBasePayload = new_default_command_payload()

    # It would make more sense to just pass in an already modified layer, but that leads to more duplication elsewhere.
    def _send(self, command_template: E58ProBasePayload, **fields):
        """Modifies the passed command layer by applying the supplied attr/value pairs,
        then sends the resulting command."""
        for field_name, field_val in fields.items():
            setattr(command_template, field_name, field_val)

        command_datagram = self._l4_base / command_template
        self._sender_func(command_datagram * self._datagrams_per_send,
                          iface=self._iface,
                          **self._send_kwargs)

    def _send_with_persist(self, **fields) -> None:
        """Persists the command state changes to subsequent sends.
        Useful for commands controlled by joysticks."""
        self._send(self._persisted_command, **fields)

    def _send_without_persist(self, **fields) -> None:
        """Does not persist the command state changes to subsequent sends.
        Useful for commands controlled by buttons that are one-time events."""
        self._send(self._persisted_command.copy(), **fields)

    def takeoff(self) -> None:
        self._send_without_persist(command=Command.TAKEOFF)

    # They're the same command.
    land = takeoff

    def stop(self) -> None:
        self._send_without_persist(command=Command.STOP)

    def roll(self) -> None:
        self._send_without_persist(command=Command.ROLL)  # TODO: Double check if a roll command is continuous or not.

    def gyro_check(self) -> None:
        self._send_without_persist(command=Command.GYRO_CHECK)

    def elevation_control(self, value: int) -> None:
        """Ascending/descending. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send_with_persist(left_vert=value)

    def turn_control(self, value: int) -> None:
        """Left/Right spin. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send_with_persist(left_horz=value)

    def direction_control(self, value: int) -> None:
        """Forwards/backwards. Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send_with_persist(right_vert=value)

    def sideways_control(self, value: int) -> None:
        """Left/Right movement (not turning). Must be a value in the range of 0x00-0xFF (inclusive)."""
        self._send_with_persist(right_horz=value)

    def reset(self) -> None:
        """Resets the internal command state to neutral fields. Should not be necessary."""
        self._persisted_command = new_default_command_payload()