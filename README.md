# Anti-drone Protection Environment

## Purpose

This is a proof-of-concept defense measure against drones entering restricted airspace.

It's able to scan for the presence of the drone, disconnect the owner if they're controlling the drone via the drone's
app, and pass control to an Xbox 360 controller.

***

## Drone

This project specifically targets the E58Pro, but the idea could be adapted for other drones once their communication
protocols are found.

***

## Usage

To run, run `main.py` and pass in arguments specifying the interface name to send/receive on, if a controller is being
intercepted or if you're directly connected to the drone, and if control should be passed to the command-line interface,
or Xbox controller:

    ./main.py --help
    usage: main.py [-h] [--connection {i,c}] [--controller {s,x}] [--interface INTERFACE] [--secs_per_channel SECS_PER_CHANNEL]
    
    optional arguments:
      -h, --help            show this help message and exit
      --connection {i,c}, -x {i,c}
                            How to interact with the drone. One of (i)nterception, (c)onnection).
      --controller {s,x}, -c {s,x}
                            What controller to use while interacting. One of (s)hell, (x)box controller.
      --interface INTERFACE, -i INTERFACE
                            The name of the interface to use. Must support monitor mode if using interception, and must either be in monitor mode already, or be in a state where monitor mode can be automatically
                            enabled.
      --secs_per_channel SECS_PER_CHANNEL, -s SECS_PER_CHANNEL
                            When using interception, how many second to stay on a channel while scanning for the drone.

***

## Controls

With the Xbox 360 controller, plug it into a USB port, and it should be automatically recognized.

The left thumb-stick controls elevation and left/right rotation.
The right thumb-stick controls forward/backward and left/right movement. `A` is "takeoff"/"land", and `Y` is "stop".

With the command-line interface, the only available commands are "takeoff" (which is also "land" if the drone is already
in the air), and "stop". There is a "help" command available too.

