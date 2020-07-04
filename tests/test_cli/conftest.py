import os
import pytest


def pytest_addoption(parser):
    parser.addoption("--cfg", action="store")


@pytest.fixture(scope="module")
def cfg(request):
    return request.config.getoption("--cfg")


@pytest.fixture(scope="module")
def testdata():
    import pandas
    return pandas.read_pickle("{}/../testdata/test.pkl".format(os.path.dirname(__file__)))
