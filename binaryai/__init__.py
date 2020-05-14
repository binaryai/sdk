from binaryai import client, function


def _get_version(default='x.x.x.dev'):
    try:
        from pkg_resources import DistributionNotFound, get_distribution
    except ImportError:
        return default
    else:
        try:
            return get_distribution(__package__).version
        except DistributionNotFound:  # Run without install
            return default
        except ValueError:  # Python 3 setup
            return default
        except TypeError:  # Python 2 setup
            return default


__version__ = _get_version()

__all__ = [
    'client',
    'function'
]

try:
    import idaapi
    from binaryai import ida
except:
    pass
else:
    __all__.append('ida')
