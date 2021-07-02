#!/usr/bin/env python3

from argparse import ArgumentParser

from scanners.channel_scanner import scan_channels
from scanners.interface_controller import InterfaceController

DEFAULT_INTERFACE = "wlx4401bb9182b7"

def main():
    parser = ArgumentParser(usage="Automatically changes the channels of the interface to scan over all "
                                  "available channels of the interface.")
    parser.add_argument("--interface", "-i", default=DEFAULT_INTERFACE)
    parser.add_argument("--time_per_channel", "-t", type=float, default=1.0)
    args = parser.parse_args()

    controller = InterfaceController(args.interface)
    controller.set_monitor_mode(True)

    try:
        while True:
            results = scan_channels(args.interface, args.time_per_channel)
            # Force result to ensure scanning. This is a bit of an abuse of scan_channels.
            list(results)
    except KeyboardInterrupt:
        pass


main()