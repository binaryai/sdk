from binaryai import client, function
from .error import BinaryAIException
import requests


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
    info = requests.get('https://pypi.org/pypi/binaryai/json').json()
    return info["info"]["version"]


__version__ = _get_version()
if "dev" not in __version__:
    _latest_version = _get_latest_version()
    if __version__.split('.')[:2] != _latest_version.split('.')[:2]:
        raise BinaryAIException("SDK_ERROR",
                                "[BinaryAI] Current version is {}, but the latest version is {}.\n"
                                "Try `pip install binaryai --upgrade` to solve this problem."
                                .format(__version__, _latest_version))

__all__ = [
    'client',
    'function',
    'BinaryAIException'
]

try:
    import idaapi   # noqa # pylint: disable=unused-import
    from binaryai import ida    # noqa # pylint: disable=unused-import
except ImportError:
    pass
else:
    __all__.append('ida')
