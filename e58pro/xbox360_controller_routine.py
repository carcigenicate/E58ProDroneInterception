from collections import Callable
from threading import Lock
import signal

from scapy.layers.inet import UDP
from xbox360controller import Xbox360Controller
from xbox360controller.controller import Button, Axis

from e58pro.command_payloads import JOYSTICK_MIN, JOYSTICK_MAX
from e58pro.controller import E58ProController

AXIS_MIN = 0
AXIS_MAX = 1


def _map_range(n: float, src_min: float, src_max: float, dst_min: float, dst_max: float) -> float:
    return dst_min + ((n - src_min) * (dst_max - dst_min) / (src_max - src_min))


def _axis_val_to_drone(axis_val: float) -> int:
    return int(_map_range(axis_val, AXIS_MIN, AXIS_MAX, JOYSTICK_MIN, JOYSTICK_MAX))


def _axis_to_drone_tup(axis: Axis) -> tuple[int, int]:
    return _axis_val_to_drone(axis.x), _axis_val_to_drone(axis.y)


def _setup_callbacks(xbox: Xbox360Controller, e58: E58ProController) -> None:
    # Since xbox_controller uses threads, and e58_controller isn't thread-safe.
    lock = Lock()

    # Button Callbacks

    def produce_btn_cb(callback: Callable[[], None]) -> Callable[[Button], None]:
        def cb(_):
            with lock:
                callback()
        return cb

    xbox.button_a.when_pressed = produce_btn_cb(e58.takeoff)
    xbox.button_b.when_pressed = produce_btn_cb(e58.stop)

    # Axis Callbacks

    def produce_axis_cb(x_handler: Callable[[int], None], y_handler: Callable[[int], None]) -> Callable[[Axis], None]:
        def cb(axis: Axis):
            with lock:
                x, y = _axis_to_drone_tup(axis)
                x_handler(x)
                y_handler(y)
        return cb

    xbox.axis_l.when_moved = produce_axis_cb(e58.turn_control, e58.elevation_control)
    xbox.axis_r.when_moved = produce_axis_cb(e58.sideways_control, e58.direction_control)


def xbox_360_control_routine(interface_name: str, l4_base: UDP) -> None:
    with Xbox360Controller() as xbox_control_input:
        e58_control_output = E58ProController(interface_name, l4_base)
        _setup_callbacks(xbox_control_input, e58_control_output)

        try:
            signal.pause()
        except KeyboardInterrupt:
            pass
        finally:
            # FIXME: SHOULD BE CHANGED TO .takeoff (land) ONCE WE START FLYING IT?
            e58_control_output.stop()  # For safety.




