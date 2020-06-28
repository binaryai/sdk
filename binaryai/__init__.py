from binaryai import client, function
from .error import BinaryAIException
import requests
import json


def _get_version(default='version not found'):
    try:
        from pkg_resources import DistributionNotFound, get_distribution
    except ImportError:
        return default
    else:
        try:
            return get_distribution(__name__).version
        except DistributionNotFound:
            return default


def _get_latest_version():
    try:
        resp = requests.get('https://pypi.org/pypi/binaryai/json')
        info = resp.content.decode()
        info = json.loads(info)
        return info["info"]["version"]
    except Exception as e:
        raise BinaryAIException("SDK_ERROR", "[BinaryAI] Check version fail.")


__version__ = _get_version()

_latest_version = _get_latest_version()
if not __version__.startswith(_latest_version):
    raise BinaryAIException("SDK_ERROR",
                            "[BinaryAI] Current version is {}, but the latest version is {}."
                            .format(__version__, _latest_version))

__all__ = [
    'client',
    'function',
    'BinaryAIException'
]

try:
    import idaapi
    from binaryai import ida
except ImportError:
    pass
else:
    __all__.append('ida')
