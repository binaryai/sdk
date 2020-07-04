import json
from click.testing import CliRunner
import binaryai as bai
from binaryai.binaryai_cli import cli


runner = CliRunner()


def format_response(response):
    return response.replace("'", '"').replace(' ', '').replace("None", "null")


def upload_function(client, func_feat, funcset_id=None):
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(
        client, func_name, func_feat, funcset_id=funcset_id)
    return func_id


def test_version():
    response = runner.invoke(cli, args=["-v"])
    assert response.exit_code == 0
    assert response.output.strip() == bai.__version__


def test_query_function(cfg, testdata):
    cfg_dict = json.load(open(cfg))
    client = bai.client.Client(url=cfg_dict['url'], token=cfg_dict['token'])
    func_feat = testdata.sample(1).iloc[0].sample(1).iloc[0]
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(client, func_name, func_feat)
    response = runner.invoke(cli, args=["query_function", "-f", func_id, "-c", cfg])
    assert response.exit_code == 0
    result = json.loads(format_response(response.output))
    assert func_id == result['id']


def test_create_funcset(cfg):
    response = runner.invoke(
        cli, args=["create_funcset", '-c', cfg])
    assert response.exit_code == 0
    result = json.loads(response.output.replace("'", '"'))
    assert "funcsetid" in result


def test_query_funcset(cfg, testdata):
    cfg_dict = json.load(open(cfg))
    client = bai.client.Client(url=cfg_dict['url'], token=cfg_dict['token'])
    func_feat = testdata.sample(1).iloc[0].sample(1).iloc[0]
    response = runner.invoke(
        cli, args=["create_funcset", "-c", cfg])
    assert response.exit_code == 0
    result = json.loads(format_response(response.output))
    funcset_id = result['funcsetid']
    upload_function(client, func_feat, funcset_id)
    response = runner.invoke(cli, args=["query_funcset", "-s", funcset_id, "-c", cfg])
    assert response.exit_code == 0
    result = json.loads(format_response(response.output))
    assert len(result['functions']) == 1
