#!/usr/bin/env python3

from argparse import ArgumentParser

from e58pro.interception_routines import connected_main, connectionless_main
from e58pro.interactive_shell_controller import interactive_shell_control_routine
from e58pro.xbox360_controller import xbox_360_control_routine

DEFAULT_INTERFACE = "wlx4401bb9182b7"
DEFAULT_CHANNEL_TIME = 0.3


def main():
    parser = ArgumentParser()
    parser.add_argument("--connection", "-x", default="i", choices="ic",
                        help="How to interact with the drone. One of (i)nterception, (c)onnection).")
    parser.add_argument("--controller", "-c", default="s", choices="sx",
                        help="What controller to use while interacting. One of (s)hell, (x)box controller.")
    parser.add_argument("--interface", "-i", default=DEFAULT_INTERFACE,
                        help="The name of the interface to use. Must support monitor mode if using interception, "
                             "and must either be in monitor mode already, or be in a state where monitor mode can be "
                             "automatically enabled.")
    parser.add_argument("--secs_per_channel", "-s", type=float, default=DEFAULT_CHANNEL_TIME,
                        help="When using interception, how many second to stay on a channel while scanning for the drone.")
    args = parser.parse_args()

    endpoint = xbox_360_control_routine if args.controller == "x" else interactive_shell_control_routine

    try:
        if args.connection == "c":
            connected_main(args.interface, endpoint)
        else:
            connectionless_main(args.interface, args.secs_per_channel, endpoint)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()