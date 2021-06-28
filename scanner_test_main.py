#!/usr/bin/env python
from scapy.layers.inet import UDP

from e58pro.auto_pwn import scan_for_drone_traffic
from e58pro.e58pro import E58ProHeader, E58ProSecondaryHeader, E58ProBasePayload

COMMAND_RECEIVE_PORT = 8800
VIDEO_SEND_PORT = 1234
DRONE_SSID = b"GD89Pro_4K"

INTERFACE = "wlx4401bb9182b7"

# App Only, Not Started:
#   - Traffic to detect: Video, Empty Comms with Seq of 0, Beacon
#   - Action to take: Disassoc App, Jam Controller (looks like w/ controller)
#
# App Only, Started:
#   - Video, Filled Comms with Seq > 0, Beacon
#   - Disassoc App
#
# Headless App w/ Controller:
#   - Video, Empty Comms with Seq of 0, Beacon
#   - Jam Controller, Disassoc app
#
# Controller only:
#   - Beacon
#   - Jam Controller

def main():
    try:
        while True:
            chan, *indicators = scan_for_drone_traffic(INTERFACE, 1, DRONE_SSID, COMMAND_RECEIVE_PORT, VIDEO_SEND_PORT)

            if any(indicators):
                # TODO: Video isn't technically required, since it should always be paired with a command.
                #        Add case to ensure that?
                video, command, beacon = indicators
                if command:
                    # Shouldn't be anything other than 0 when being controlled by app.
                    if command[E58ProBasePayload].controller_header == 0:
                        print("Being controlled headless with controller, "
                              "or the app is still warming up or hasn't entered control mode yet.")
                    else:
                        print("Only app is connected.")
                elif beacon:
                    print("Only controlled is connected.")
                else:
                    print(f"Unknown state!: Channel: {chan}, Indicators: {[bool(i) for i in indicators]}")
    except KeyboardInterrupt:
        pass


main()
