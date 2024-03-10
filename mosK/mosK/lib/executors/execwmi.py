from ..target import Target
from rich.panel import Panel

import os
import ntpath
import tempfile
import time
from impacket.smbconnection import SessionError


class ExecWMI:
    SMB_OUT_DIR = "\\Windows\\Temp\\"
    WMI_OUT_DIR = "C:\\Windows\\Temp\\"
    SMB_SHARE = "C$"
    CMD = "cmd /c {command} > {out} 2>&1"
    def __init__(self, target: Target) -> None:
        self._target = target
        if not self._connected:
            login = self._target._console.input("execwmi will only work if there is WMI + SMB connection established\nLogin [Y/n]")
            if login.lower() == "" or login.lower() == "y":
                self.login()
            else:
                raise ConnectionError("execwmi will only work if there is WMI + SMB connection established")
        self._temp_file_name = os.path.split(tempfile.NamedTemporaryFile().name)[1]
        self.WMI_OUT_PATH = ntpath.join(self.WMI_OUT_DIR, self._temp_file_name)
        self.SMB_OUT_PATH = ntpath.join(self.SMB_OUT_DIR, self._temp_file_name)
        self._target._console.print(Panel(f"temp out file is: [grey bold]{self._temp_file_name}[/grey bold]"))
        self._target.smb.use_share(self.SMB_SHARE)
        
    
    
    @property
    def _connected(self) -> bool:
        """
        execwmi will only work if there is WMI + SMB connection established

        Returns:
            bool: returns true if can pressed
        """
        return self._target.wmi._connected and self._target.smb._connected

    def login(self):
        if self._connected:
            return
        self._target.wmi.login()
        self._target.smb.login()
        

    def shell(self):
        self._target._console.print("starting shell [CTRL+D to close]...")
        while True:
            try:
                cmd = self._target._console.input(">> ")
                self.execute(cmd)
            except KeyboardInterrupt:
                self._target._console.print()
                continue
            except EOFError:
                self._target._console.print("closing shell...")
                try:
                    os.remove(self._temp_file_name)
                except:
                    pass
                break

    def execute(self, command: str):
        cmd = self.CMD.format(command=command, out=self.WMI_OUT_PATH)
        self._target._console.log("creating process...")
        self._target.wmi.create_process(cmd)
        self._target._console.log("reading file")
        time.sleep(2)
        while True:
            try:
                self._target.smb.download_file(self.SMB_OUT_PATH)
                break
            except SessionError:
                self._target._console.log("process is still not done...")
                time.sleep(2)
                continue
        with open(self._temp_file_name, "r") as f:
            data = f.read()
        self._target._console.print(data)
        os.remove(self._temp_file_name)