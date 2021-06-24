import subprocess as sp


class InterfaceController:
    def __init__(self, interface_name):
        self.name = interface_name

    def _checked_iwconfig(self, *commands) -> None:
        completed = sp.run(["iwconfig", self.name, *commands], capture_output=True)
        if completed.returncode != 0:
            err = completed.stderr
            if b"Operation not permitted" in err:
                msg = f"This script requires root permissions."
            elif b"No such device" in err:
                msg = f"Invalid interface name: {self.name}"
            else:
                msg = f"Unknown error: {err}"
            raise RuntimeError(msg)

    def set_channel(self, new_channel: int) -> None:
        self._checked_iwconfig("channel", str(new_channel))

    def set_monitor_mode(self, should_enable: bool) -> None:
        mode = "monitor" if should_enable else "managed"
        self._checked_iwconfig("mode", mode)

    def get_supported_channels(self) -> list[int]:
        completed = sp.run(["iwlist", self.name, "channel"], capture_output=True)
        if completed.stderr:
            raise RuntimeError(f"Error: {completed.stderr}")
        else:
            try:
                decoded = completed.stdout.decode("UTF-8").strip()
                # Cutting off bad header and footer
                lines = decoded.split("\n")[1:][:-1]  # FIXME: Eww
                raw_chans = [line.split()[1] for line in lines]
                return [int(raw) for raw in raw_chans]
            except (IndexError, ValueError) as e:
                raise RuntimeError(f"Error reading iwlist: {e}")