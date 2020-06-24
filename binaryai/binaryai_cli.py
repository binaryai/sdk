#!/usr/bin/env python
from binaryai.client import Client
from binaryai.function import query_function, create_function_set, query_function_set, search_sim_funcs
import click


@click.group(invoke_without_command=True)
@click.option('--url', '-u', type=str, help='api url',
              default="https://api.binaryai.tencent.com/v1/endpoint", show_default=True)
@click.option('--token', '-t', type=str, help='user token')
@click.option('--help', '-h', is_flag=True, help='Show this message and exit.')
@click.option('--version', '-v', is_flag=True, help='Show version')
@click.pass_context
def cli(ctx, url, token, help, version):
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
    client = Client(token, url)
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


@cli.command('search_funcs', short_help='search top similar functions of the query')
@click.option('--funcid', '-f', help='function id', type=str, required=True)
@click.option('--funcset', '-s', multiple=True, type=str, help='funcset ids, set multi ids with -s id1 -s id2')
@click.option('--topk', '-k', type=int, default=10, show_default=True, help='return first topk results')
@click.pass_context
def SearchFuncs(ctx, funcid, funcset, topk):
    client = ctx.obj
    result = search_sim_funcs(client, funcid, list(funcset), topk)
    click.echo(result)


def main():
    cli()
