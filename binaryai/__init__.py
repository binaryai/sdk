from binaryai import client, function
from .error import BinaryAIException


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


__version__ = _get_version()

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
