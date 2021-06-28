#!/usr/bin/env python3

from argparse import ArgumentParser

from e58pro.auto_pwn import connected_main, connectionless_main

DEFAULT_INTERFACE = "wlx4401bb9182b7"
DEFAULT_CHANNEL_TIME = 0.3


def main():
    parser = ArgumentParser()
    parser.add_argument("--connected", "-c", action="store_true", default=False)
    parser.add_argument("--interface", "-i", default=DEFAULT_INTERFACE)
    parser.add_argument("--secs_per_channel", "-s", type=float, default=DEFAULT_CHANNEL_TIME)
    args = parser.parse_args()

    try:
        if args.connected:
            connected_main(args.interface)
        else:
            connectionless_main(args.interface, args.secs_per_channel)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()