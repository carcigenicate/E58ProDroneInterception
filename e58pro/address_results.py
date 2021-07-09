from typing import NamedTuple


class AddressResults(NamedTuple):
    drone_mac: str
    drone_ip: str
    controller_mac: str
    controller_ip: str