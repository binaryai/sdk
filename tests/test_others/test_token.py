import binaryai as bai
from binaryai import BinaryAIException


def test_token_verify(url):
    token = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    try:
        bai.client.Client(url=url, token=token)
    except BinaryAIException as e:
        assert e._msg == "UNAUTHENTICATED: Invalid token"
