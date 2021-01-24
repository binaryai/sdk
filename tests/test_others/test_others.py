import binaryai as bai
from binaryai.cli import cli
from binaryai import BinaryAIException
from click.testing import CliRunner


def test_token_verify(url):
    token = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    try:
        bai.client.Client(url=url, token=token)
    except BinaryAIException as e:
        assert e._msg == "UNAUTHENTICATED: Invalid token"


def test_version():
    runner = CliRunner()
    response = runner.invoke(cli, args=["-v"])
    assert response.exit_code == 0
    assert response.output.strip() == bai.__version__
