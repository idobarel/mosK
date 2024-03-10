from impacket.smbconnection import SMBConnection
import time
from rich.panel import Panel
import ntpath
from typing import *

from ..helper import parse_target, Console

class SMB:
    """
    SMB class
    """
    def __init__(self, target: str, console: Console) -> None:
        self._domain, self._username, self._password, self._remote = parse_target(target)
        self._console = console
        self._connected = False
        self._share = None
    
    def _get_info(self) -> None:
        tmp_conn = SMBConnection(self._remote, self._remote)
        target_os = f'{tmp_conn.getServerOSMajor()}.{tmp_conn.getServerOSMinor()}'
        domain = tmp_conn.getServerDomain()
        hostname = tmp_conn.getServerDNSHostName()
        s = f"[bold blue]{domain}\\{hostname}[/bold blue] [magenta]{target_os}[/magenta]"
        self._console.print(Panel(s))
    
    def login(self):
        """
        Login to the remote target, establish SMB connection
        """
        with self._console.status("Starting SMB connection to the target...") as _:
            self._console.log("Creating connection...")
            self._conn = SMBConnection(self._remote, self._remote)
            self._console.log("Logging in...")
            self._conn.login(self._username, self._password, self._domain)
            self._console.log("[green]success[/green]")
        self._connected = True
        
    def list_shares(self, display: bool = True) -> Union[None, List[str]]:
        """
        List the remote shares

        Args:
            display (bool, optional): display to the screen. Defaults to True.

        Raises:
            ConnectionError: If the SMB connection is not established

        Returns:
            Union[None, List[str]]: None if display is True, else share list
        """
        if not self._connected:
            raise ConnectionError("Not Connected to target!")
        shares = self._conn.listShares()
        _shares = []
        shares_string = ""
        for share in shares:
            if display:
                shares_string += share['shi1_netname'][:-1] + "\n"
            else:
                _shares.append(share['shi1_netname'][:-1])
        if display:
            self._console.print(Panel(shares_string))
        else:
            return _shares
    
    def use_share(self, share_name: str):
        """
        Use a remote share

        Args:
            share_name (str): the share to use

        Raises:
            ConnectionError: If the SMB connection is not established
        """
        if not self._connected:
            raise ConnectionError("Not Connected to target!")
        with self._console.status(f"Connecting to share {share_name}...") as _:
            self._console.log("creating connection...")
            self._conn.connectTree(share_name)
            self._console.log("[green]success[/green]")
        self._share = share_name
        
    def list_path(self, path: str, display: bool = True) -> Union[None, List[Dict[str, str]]]:
        """
        List a remote path

        Args:
            path (str): the path to list (must be a path from the used share)
            display (bool, optional): display the output, or just save to array. Defaults to True.

        Raises:
            ConnectionError: If the SMB connection is not established
            ValueError: If no share is used

        Returns:
            Union[None, List[Dict[str, str]]]: None if display is true, else the list of files
        """
        if not self._connected:
            raise ConnectionError("Not Connected to target!")
        if self._share == None:
            raise ValueError("No share is used!")
        if path == '':
           pwd = ntpath.join("\\",'*')
        else:
            pwd = ntpath.join(path,'*')
        pwd = pwd.replace('/','\\')
        pwd = ntpath.normpath(pwd)
        display_string = ""
        files = []
        for f in self._conn.listPath(self._share, pwd):
            if display is True:
                display_string += "%crw-rw-rw- %10d  %s %s" % (
                'd' if f.is_directory() > 0 else '-', f.get_filesize(), time.ctime(float(f.get_mtime_epoch())),
                f.get_longname()) + "\n"
            else:
                files.append({
                    "name": f.get_longname(),
                    "size": f.get_filesize(),
                    "is_dir": f.is_directory(),
                    "last_time_modified": time.ctime(float(f.get_mtime_epoch()))
                })
        if display is True:
            self._console.print(Panel(display_string))
            return None
        else:
            return files


    def download_file(self, r_filename: str, func: Callable = None):
        with self._console.status(f"Downloading file [yellow]{r_filename}[/yellow] from share [cyan]{self._share}[cyan]") as _:
            filename = ntpath.basename(r_filename)
            if func == None:
                with open(filename, "wb") as f:
                    self._conn.getFile(self._share, r_filename, f.write)
                self._console.print(f"saved to [green]{filename}[/green]")
            else:
                self._conn.getFile(self._share, r_filename, func)
                

    def upload_file(self, l_filename: str, r_path: str):
        with self._console.status(f"Uploading file [yellow]{l_filename}[/yellow] from share [cyan]{self._share}[cyan]") as _:
            with open(l_filename, "rb") as f:
                self._conn.putFile(self._share, r_path, f.read)
            self._console.print(f"[yellow]{l_filename}[/yellow] has been uploaded to [green]{r_path}[/green]")

    def close(self):
        if self._connected:
            self._conn.close()

    def __repr__(self) -> str:
        smb_string = "SMB: [green]connected[/green]" if self._connected else "SMB: [red]disconnected[/red]"
        self._console.print("")
        p = Panel(f"{smb_string}")
        self._console.print(p)
        return ""