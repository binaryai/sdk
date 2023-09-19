import warnings

from .binaryai_file import BinaryAIFile
from .client import SDK_VERSION, BinaryAI
from .component import Component
from .compressed_file import CompressedFile
from .cve import CVE
from .exceptions import FileNotExistError, FileRequiredError
from .function import Function
from .license import License

__version__ = SDK_VERSION

# Add deprecation warnings
warnings.filterwarnings("default", category=DeprecationWarning)
warnings.filterwarnings("default", category=PendingDeprecationWarning)

__all__ = [
    BinaryAI,
    BinaryAIFile,
    Component,
    CompressedFile,
    CVE,
    FileNotExistError,
    FileRequiredError,
    Function,
    License,
]
