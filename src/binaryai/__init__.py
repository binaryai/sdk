import warnings
from importlib.metadata import version

from gql.transport.requests import RequestsHTTPTransport

from .binaryai_file import BinaryAIFile
from .client import BinaryAI
from .component import Component
from .compressed_file import CompressedFile
from .cve import CVE
from .exceptions import (
    BinaryAIException,
    BinaryAIGQLError,
    BinaryAIGQLErrorDetail,
    BinaryAIResponseError,
    FileNotExistError,
)
from .function import Function
from .license import License

__version__ = version("pycounts")

# Add deprecation warnings
warnings.filterwarnings("default", category=DeprecationWarning)
warnings.filterwarnings("default", category=PendingDeprecationWarning)

__all__ = [
    BinaryAI,
    BinaryAIFile,
    Component,
    CompressedFile,
    CVE,
    BinaryAIException,
    BinaryAIGQLError,
    BinaryAIGQLErrorDetail,
    BinaryAIResponseError,
    FileNotExistError,
    Function,
    License,
    RequestsHTTPTransport,
]
