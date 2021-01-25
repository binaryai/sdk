import os
import pytest


def pytest_addoption(parser):
    parser.addoption("--url", action="store")
    parser.addoption("--token", action="store")


@pytest.fixture(scope="module")
def client(request):
    from binaryai.client import Client
    url = request.config.getoption("--url")
    token = request.config.getoption("--token")
    return Client(url=url, token=token)


@pytest.fixture(scope="module")
def data_1():
    import pandas
    return pandas.read_pickle("{}/../testdata/test.pkl".format(os.path.dirname(__file__)))
