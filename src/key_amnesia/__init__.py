"""keygate: AI agents use your secrets without seeing them."""

from importlib.metadata import PackageNotFoundError, version as _version

try:
    __version__ = _version("keygate-cli")
except PackageNotFoundError:
    try:
        __version__ = _version("key-amnesia")
    except PackageNotFoundError:
        __version__ = "0.0.0"
