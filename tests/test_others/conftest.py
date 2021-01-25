import os
import pytest


def pytest_addoption(parser):
    parser.addoption("--url", action="store")
    parser.addoption("--token", action="store")


@pytest.fixture(scope="module")
def url(request):
    return request.config.getoption("--url")


@pytest.fixture(scope="module")
def token(request):
    return request.config.getoption("--token")


@pytest.fixture(scope="module")
def testdata():
    import pandas
    return pandas.read_pickle("{}/../testdata/test.pkl".format(os.path.dirname(__file__)))
