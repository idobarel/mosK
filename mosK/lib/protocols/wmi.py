from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from rich.panel import Panel
from rich.table import Table
from typing import *

from ..helper import parse_target, Console

class WMI:
    """
    SMB class
    """
    def __init__(self, target: str, console: Console) -> None:
        self._domain, self._username, self._password, self._remote = parse_target(target)
        self._console = console
        self._connected = False
        self._share = None
    
    def login(self):
        """
        Login to the remote target, establish WMI connection
        """
        with self._console.status("Starting WMI connection to the target...") as _:
            self._console.log("Creating connection...")
            self._dcom = DCOMConnection(self._remote, self._username, self._password, self._domain, oxidResolver=True)
            iInterface = self._dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            self._console.log("Logging in...")
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            self._proc_obj, _ = iWbemServices.GetObject("Win32_Process")
            self._console.log("[green]success[/green]")
            self._connected = True
            self._conn = iWbemServices
    
    def _build_table(self, iEnum: wmi.IEnumWbemClassObject) -> Table:
        """
        Build the output table

        Args:
            iEnum (wmi.IEnumWbemClassObject): input object

        Returns:
            rich.table.Table: the output table
        """
        table = Table()
        _first = True
        while True:
            try: 
                pEnum: wmi.IWbemClassObject = iEnum.Next(0xffffffff,1)[0]
                record = pEnum.getProperties()
                if _first:
                    for col in record:
                        table.add_column(col)
                    _first = False
                data = []
                for key in record:
                    if type(record[key]['value']) is list:
                        tmp = []
                        for item in record[key]['value']:
                            tmp.append(str(item))
                        tmp = "\n".join(tmp)
                        data.append(tmp)
                    else:
                        data.append(str(record[key]['value']))
                table.add_row(*data)
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break
        iEnum.RemRelease()
        return table
    
    def query(self, query: str):
        """
        Run a WMI query on target machine

        Args:
            query (str): the query to run
        """
        out = self._conn.ExecQuery(query)
        out_table = self._build_table(out)
        self._console.print(out_table)
        out.RemRelease()

    def create_process(self, cmd: str, directory: str = "C:\\"):
        with self._console.status(f"Creating process [cyan]{cmd}[/cyan]...") as _:
            out = self._proc_obj.Create(cmd, directory, None)
            pid, rval = out.ProcessId,out.ReturnValue
            rval_str = f"ReturnValue: [red]{rval}[/red]" if rval == 0 else f"ReturnValue: [green]{rval}[/green]"
            pid_str = f"ProcessId: [red]{pid}[/red]" if rval == 0 else f"ReturnValue: [green]{pid}[/green]"
            final_str = f"{rval_str}\n{pid_str}"
            self._console.print(Panel(final_str))


    def close(self):
        if self._connected:
            self._dcom.disconnect()

    def __repr__(self) -> str:
        smb_string = "WMI: [green]connected[/green]" if self._connected else "SMB: [red]disconnected[/red]"
        self._console.print("")
        p = Panel(f"{smb_string}")
        self._console.print(p)
        return ""