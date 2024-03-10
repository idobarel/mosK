import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--script", default=None, help="python script to run before the IPython shell starts")
    return parser.parse_args()

def main():
    from lib.target import Console
    console = Console()
    console.log("importing libraries...")
    from lib.target import Target, TARGETS
    from lib.utils import DPAPI, Chrome
    from lib.executors.execwmi import ExecWMI
    import IPython
    from traitlets.config import get_config
    args = get_args()
    if args.script != None:
        console.log("Running script...")
        with open(args.script, "r") as f:
            exec(f.read(), globals(), locals())
    console.log("generating colors...")
    c = get_config()
    c.InteractiveShellEmbed.colors = "Linux"
    console.log("starting IPython...")
    IPython.embed(config=c)
    with console.status("Cleaning up...") as _:
        console.log("closing target connections...")
        for tmp in TARGETS:
            tmp.clear()
    console.print("[green]done[/green]")


if __name__ == '__main__':
    main()
