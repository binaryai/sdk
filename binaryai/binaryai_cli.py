#!/usr/bin/env python
from binaryai.client import Client
from binaryai.function import query_function, create_function_set, query_function_set, search_sim_funcs
import platform
import click
import json
import os
import shutil


def get_default_ida_path():
    platf = platform.system()
    if platf == 'Windows':
        hexrays_path = os.path.join(os.getenv('APPDATA'), "Hex-Rays")
        return os.path.join(hexrays_path, "IDA Pro")
    elif platf == 'Linux':
        return os.path.join(os.path.expanduser('~'), ".idapro")
    else:
        print("Platform {} is not supported for BinaryAI command tools.".format(platf))
        exit(0)


@click.group(invoke_without_command=True)
@click.option('--cfg', '-c', default=None, help='Load BinaryAI configure file')
@click.option('--help', '-h', is_flag=True, help='Show this message and exit.')
@click.option('--version', '-v', is_flag=True, help='Show version')
@click.option('--install', '-i', type=str, help='Install IDA plugin')
@click.option('--ida_plugins', '-d', help='IDA plugins path (default is "$IDAUSR/plugins/", "~/.idapro/plugins/")')
@click.pass_context
def cli(ctx, cfg, help, version, install, ida_plugins):
    # get IDA path, and check IDA Pro installed
    ida_path = get_default_ida_path()
    if not os.path.exists(ida_path):
        print("You need to install IDA Pro!")
        ctx.exit()

    if install:
        if ida_plugins:
            if not os.path.exists(ida_plugins):
                os.mkdir(ida_plugins)
        else:
            ida_plugins = os.path.join(ida_path, "plugins")
            if not os.path.exists(ida_plugins):
                os.mkdir(ida_plugins)
        shutil.copy(install, ida_plugins)
        print('Install "{}" to "{}"'.format(install, ida_plugins))
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

    if not cfg:
        cfg_dir = os.path.join(ida_path, "cfg")
        cfg = os.path.join(cfg_dir, "binaryai.cfg")

    cfg_dir = {}
    with open(cfg, "r") as f:
        cfg_dic = json.load(f)
    client = Client(cfg_dic['token'], cfg_dic['url'])
    ctx.obj = client


@cli.command('query_function', short_help='get function info by given id')
@click.option('--funcid', '-f', help='function id', required=True)
@click.pass_context
def QueryFunction(ctx, funcid):
    client = ctx.obj
    result = query_function(client, funcid)
    click.echo(result)


@cli.command('create_funcset', short_help='create a new function set and add functions if needed')
@click.option('--funcid', '-f', multiple=True, type=str, help='function ids, set multi ids with -i id1 -i id2')
@click.pass_context
def CreateFuncSet(ctx, funcid):
    client = ctx.obj
    result = create_function_set(client, list(funcid))
    click.echo({'funcsetid': result})


@cli.command('query_funcset', short_help='get function set info by id')
@click.option('--funcset', '-s', help='funcset id', type=str, required=True)
@click.pass_context
def QueryFuncSet(ctx, funcset):
    client = ctx.obj
    result = query_function_set(client, funcset)
    click.echo(result)


def main():
    cli()
