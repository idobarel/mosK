from rich.panel import Panel


from .helper import parse_target, Console, TARGETS
from .protocols.smb import SMB
from .protocols.wmi import WMI



class Target:
    """
    A target (connection) handler class
    """
    def __init__(self, target: str) -> None:
        """
        Target init

        Args:
            target (str): the target string (impacket like string)
        """
        self._console = Console()
        self._target = target
        self.domain, self.username, self.password, self.remote = parse_target(target)
        self.wmi = WMI(self._target, self._console)
        self.smb = SMB(self._target, self._console)
        TARGETS.append(self)

    def clear(self):
        self.smb.close()
        self.wmi.close()

    def login_all(self):
        self._console.log("initialzing SMB connection...")
        self.smb.login()
        self._console.log("initialzing WMI connection...")
        self.wmi.login()
            
        self._console.print("[green]done[/green]")

    def __repr__(self) -> str:
        smb_string = "SMB: [green]connected[/green]" if self.smb._connected else "SMB: [red]disconnected[/red]"
        wmi_string = "WMI: [green]connected[/green]" if self.wmi._connected else "WMI: [red]disconnected[/red]"
        self._console.print("")
        p = Panel(f"{smb_string}\n{wmi_string}")
        self._console.print(p)
        return ""