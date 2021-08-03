import time
from collections import Callable
from threading import Lock, Event, Thread
import signal
from time import sleep
from typing import TypeVar, Generic

from scapy.layers.dot11 import RadioTap, Dot11FCS, Dot11QoS
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Packet
from xbox360controller import Xbox360Controller
from xbox360controller.controller import Button, Axis

from e58pro.controller import E58ProController
from e58pro.transmitter_process import TransmitterProcessController

AXIS_MIN = -1
AXIS_MAX = 1

JOYSTICK_MIN = 0x00
JOYSTICK_MAX = 0xFF
JOYSTICK_NEUTRAL = 0x80
JOYSTICK_RADIUS = JOYSTICK_MAX - JOYSTICK_NEUTRAL

LAT_MOVEMENT_SPEED_PERC = 0.5
ELEV_TURN_SPEED_PERC = 0.7

JOYSTICK_UPDATES_PER_SECOND = 10


def _map_range(n: float, src_min: float, src_max: float, dst_min: float, dst_max: float) -> float:
    """Maps n from the range [src_min, src_max] to the range [dst_min, dst_max]."""
    return dst_min + ((n - src_min) * (dst_max - dst_min) / (src_max - src_min))


def _speed_offset_from_perc(speed_perc: float) -> int:
    return int(JOYSTICK_RADIUS * speed_perc)


def _axis_val_to_drone(axis_val: float, speed_perc: float) -> int:
    offset = _speed_offset_from_perc(speed_perc)
    return int(_map_range(axis_val, AXIS_MIN, AXIS_MAX, JOYSTICK_NEUTRAL - offset, JOYSTICK_NEUTRAL + offset))


def _axis_to_drone_tup(axis: Axis, speed_perc: float) -> tuple[int, int]:
    return _axis_val_to_drone(axis.x, speed_perc), _axis_val_to_drone(axis.y, speed_perc)


def _setup_button_callbacks(xbox: Xbox360Controller, e58: E58ProController, controller_lock: Lock) -> None:
    def produce_btn_cb(callback: Callable[[], None]) -> Callable[[Button], None]:
        def cb(_):
            with controller_lock:
                callback()
        return cb

    xbox.button_a.when_pressed = produce_btn_cb(e58.takeoff)
    xbox.button_y.when_pressed = produce_btn_cb(e58.stop)


def _invert_axis_value(axis_val: int) -> int:
    return JOYSTICK_NEUTRAL + (JOYSTICK_NEUTRAL - axis_val)


def _start_axis_sender(xbox_input: Xbox360Controller,
                       controller_lock: Lock,
                       left_speed_perc: float,
                       right_speed_perc: float,
                       left_x_handler: Callable[[int], None],
                       left_y_handler: Callable[[int], None],
                       right_x_handler: Callable[[int], None],
                       right_y_handler: Callable[[int], None]
                       ) -> Event:
    termination_event = Event()

    def update_routine():
        last_left = None
        last_right = None
        while not termination_event.is_set():
            # Awful for a few reasons. Making use of .when_moved on the Axis objects would be much cleaner, but it
            #  proved to be too unreliable (many events were missed).
            # This also relies on CPython assignments being atomic. The XBoxController library sets the x and y
            #  attributes in another thread, but doesn't do any locking to make the class thread-safe.
            left = _axis_to_drone_tup(xbox_input.axis_l, left_speed_perc)
            right = _axis_to_drone_tup(xbox_input.axis_r, right_speed_perc)

            with controller_lock:
                if left != last_left:  # Optimizations to avoid needless requests since the requests are persistent.
                    print("Setting left to", *map(hex, left))
                    left_x_handler(left[0])
                    left_y_handler(left[1])
                    last_left = left

                if right != last_right:
                    print("Setting right to", *map(hex, right))
                    right_x_handler(right[0])
                    right_y_handler(right[1])
                    last_right = right

            sleep(1 / JOYSTICK_UPDATES_PER_SECOND)

    thread = Thread(target=update_routine)
    thread.start()

    return termination_event


def xbox_360_control_routine(proc_controller: TransmitterProcessController) -> None:
    e58_lock = Lock()
    with Xbox360Controller() as xbox_control_in:
        e58_control_out = E58ProController(proc_controller, 5)
        _setup_button_callbacks(xbox_control_in, e58_control_out, e58_lock)

        termination_event = \
            _start_axis_sender(xbox_control_in,
                               e58_lock,
                               ELEV_TURN_SPEED_PERC,
                               LAT_MOVEMENT_SPEED_PERC,
                               e58_control_out.turn_control,
                               # Inverting because up is 0x00 on the XBox, but 0xFF for the drone.
                               lambda n: e58_control_out.elevation_control(_invert_axis_value(n)),
                               e58_control_out.sideways_control,
                               lambda n: e58_control_out.direction_control(_invert_axis_value(n)))

        try:
            signal.pause()
        except KeyboardInterrupt:
            pass
        finally:
            termination_event.set()
