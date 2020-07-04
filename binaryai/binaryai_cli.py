#!/usr/bin/env python
from binaryai.client import Client
from binaryai.function import query_function, create_function_set, query_function_set
import platform
import click
import json
import os


def get_default_ida_path():
    current_platform = platform.system()
    if current_platform == 'Windows':
        hexrays_path = os.path.join(os.getenv('APPDATA'), "Hex-Rays")
        return os.path.join(hexrays_path, "IDA Pro")
    elif current_platform == 'Linux' or current_platform == 'Darwin':
        return os.path.join(os.path.expanduser('~'), ".idapro")
    else:
        return ""


@click.group(invoke_without_command=True)
@click.option('--help', '-h', is_flag=True, help='show this message and exit.')
@click.option('--version', '-v', is_flag=True, help='show version')
@click.pass_context
def cli(ctx, help, version):
    # get IDA path, and check IDA Pro installed
    ida_path = get_default_ida_path()
    if not os.path.isdir(ida_path):
        print("$IDAUSR path not found")
        ctx.exit()

    if ctx.invoked_subcommand is None or help:
        if version:
            import binaryai
            click.echo(binaryai.__version__)
            ctx.exit()
        else:
            banner = r'''
 ____  _                           _    ___
| __ )(_)_ __   __ _ _ __ _   _   / \  |_ _|
|  _ \| | '_ \ / _` | '__| | | | / _ \  | |
| |_) | | | | | (_| | |  | |_| |/ ___ \ | |
|____/|_|_| |_|\__,_|_|   \__, /_/   \_\___|
                          |___/
        '''
            click.echo(banner)
            click.echo(ctx.get_help())
            ctx.exit()


@cli.command('install_ida_plugin', short_help='install IDA plugin')
@click.option('--directory', '-d', help='IDA plugin directory', default=None)
@click.pass_context
def InstallPlugin(ctx, directory):
    ida_path = get_default_ida_path()
    if directory and not os.path.isdir(directory):
        click.echo('Invalid plugin path')
        ctx.exit()
    if not directory:
        directory = os.path.join(ida_path, "plugins")
    os.makedirs(directory) if not os.path.exists(directory) else None
    store_path = os.path.join(directory, 'ida_binaryai.py')
    click.echo("installing ida_binaryai.py into {}...".format(directory))
    plugin_code = """import idaapi
import binaryai.ida_binaryai

class Plugin(idaapi.plugin_t):
    wanted_name = "BinaryAI"
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE

    def init(self):
        if binaryai.ida_binaryai.load_ida_plugin():
            return idaapi.PLUGIN_OK
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    return Plugin()
    """
    try:
        with open(store_path, "w") as f:
            f.write(plugin_code)
            f.close()
    except Exception:
        click.echo("Error while installing ida_binaryai.py.")
        ctx.exit()
    click.echo("Done")


@cli.command('query_function', short_help='get function info by given id')
@click.option('--funcid', '-f', help='function id', required=True)
@click.option('--cfg', '-c', default=None, help='load binaryai configure file')
@click.pass_context
def QueryFunction(ctx, funcid, cfg):
    ida_path = get_default_ida_path()
    if not cfg:
        import binaryai
        cfg = os.path.join(ida_path, "cfg", "{}.cfg".format(binaryai.__name__))

    with open(cfg, "r") as f:
        cfg_dic = json.load(f)
    client = Client(cfg_dic['token'], cfg_dic['url'])
    result = json.dumps(query_function(client, funcid), sort_keys=True, indent=4, separators=(',', ';'))
    click.echo(result)


@cli.command('create_funcset', short_help='create a new function set and add functions if needed')
@click.option('--funcid', '-f', multiple=True, type=str, help='function ids, set multi ids with -i id1 -i id2')
@click.option('--cfg', '-c', default=None, help='load binaryai configure file')
@click.pass_context
def CreateFuncSet(ctx, funcid, cfg):
    ida_path = get_default_ida_path()
    if not cfg:
        import binaryai
        cfg = os.path.join(ida_path, "cfg", "{}.cfg".format(binaryai.__name__))
    with open(cfg, "r") as f:
        cfg_dic = json.load(f)
    client = Client(cfg_dic['token'], cfg_dic['url'])
    result = create_function_set(client, list(funcid))
    click.echo({'funcsetid': result})


@cli.command('query_funcset', short_help='get function set info by id')
@click.option('--funcset', '-s', help='funcset id', type=str, required=True)
@click.option('--cfg', '-c', default=None, help='load binaryai configure file')
@click.pass_context
def QueryFuncSet(ctx, funcset, cfg):
    ida_path = get_default_ida_path()
    if not cfg:
        import binaryai
        cfg = os.path.join(ida_path, "cfg", "{}.cfg".format(binaryai.__name__))
    with open(cfg, "r") as f:
        cfg_dic = json.load(f)
    print(cfg_dic['token'], cfg_dic['url'])
    client = Client(cfg_dic['token'], cfg_dic['url'])
    result = json.dumps(query_function_set(client, funcset), sort_keys=True, indent=4, separators=(',', ':'))
    click.echo(result)


def main():
    cli()
