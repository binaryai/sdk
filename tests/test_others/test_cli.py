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


def test_query_function(url, token, testdata):
    client = bai.client.Client(url=url, token=token)
    func_feat = testdata.sample(1).iloc[0].sample(1).iloc[0]
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(client, func_name, func_feat)
    response = runner.invoke(cli, args=["-u", url, "-t", token, "query_function", "-f", func_id])
    assert response.exit_code == 0
    result = json.loads(format_response(response.output))
    assert func_id == result['id']


def test_create_funcset(url, token):
    response = runner.invoke(
        cli, args=["-u", url, "-t", token, "create_funcset"])
    assert response.exit_code == 0
    result = json.loads(response.output.replace("'", '"'))
    assert "funcsetid" in result


def test_query_funcset(url, token, testdata):
    client = bai.client.Client(url=url, token=token)
    func_feat = testdata.sample(1).iloc[0].sample(1).iloc[0]
    func_id = upload_function(client, func_feat)
    response = runner.invoke(
        cli, args=["-u", url, "-t", token, "create_funcset", "-f", func_id])
    assert response.exit_code == 0
    result = json.loads(format_response(response.output))
    funcset_id = result['funcsetid']
    response = runner.invoke(cli, args=["-u", url, "-t", token, "query_funcset", "-s", funcset_id])
    assert response.exit_code == 0
    result = json.loads(format_response(response.output))
    assert len(result['functions']) == 1


def test_search_sim_func(url, token, testdata):
    client = bai.client.Client(url=url, token=token)
    response = runner.invoke(
        cli, args=["-u", url, "-t", token, "create_funcset"])
    assert response.exit_code == 0
    result = json.loads(response.output.replace("'", '"'))
    assert "funcsetid" in result
    funcset_id = result['funcsetid']
    func_feat = testdata.sample(1).iloc[0].sample(1).iloc[0]
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(
        client, func_name, func_feat, funcset_id=funcset_id)
    response = runner.invoke(cli, args=[
                             "-u", url, "-t", token, "search_funcs", "-f", func_id, "-s", funcset_id, "-k", 1])
    assert response.exit_code == 0
    result = json.loads(format_response(response.output))
    assert len(result) == 1
    assert result[0]['function']['id'] == func_id
