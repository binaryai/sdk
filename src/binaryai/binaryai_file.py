from typing import Dict, Iterator, List

from binaryai.client import BinaryAI
from binaryai.component import Component
from binaryai.compressed_file import CompressedFile
from binaryai.cve import CVE
from binaryai.function import Function, MatchedFunction
from binaryai.license import License


class BinaryAIFile(object):
    """BinaryAIFile represent the file already analyzed by BinaryAI.
    Users can receive the detailed results by using this conveniently.
    Note: This is not thread safe!!!
    """

    def __init__(self, bai: BinaryAI, sha256: str = None, md5: str = None) -> None:
        if sha256 is None and md5 is None:
            raise ValueError("sha256 and md5 can not empty simultaneously")
        if sha256 is None:
            self.sha256 = bai.get_sha256(md5)
        else:
            self.sha256 = sha256
        self.md5 = md5
        self._bai = bai

    def get_filenames(self) -> List[str]:
        """Get all uploaded filenames.

        Returns:
            List[str]: A list of filenames.
        """
        return self._bai.get_filenames(self.sha256)

    def get_mime_type(self) -> str:
        """Get MIME type

        Returns:
            str: MIME type string.
        """
        return self._bai.get_mime_type(self.sha256)

    def get_size(self) -> int:
        """Get size in bytes.

        Returns:
            int: File size in bytes.
        """
        return self._bai.get_size(self.sha256)

    def get_compressed_files(self) -> List[CompressedFile]:
        """Get a list of files inside a compressed file identified.

        Returns:
            List[CompressedFile]: A list of compressed files.
        """
        return self._bai.get_compressed_files(self.sha256)

    def get_all_cves(self) -> List[CVE]:
        """Get all CVEs.

        Returns:
            List[str]: A list of CVE objects.
        """
        return self._bai.get_all_cves(self.sha256)

    def get_all_cve_names(self) -> List[str]:
        """Get all CVE names.

        Returns:
            List[str]: A list of CVE names.
        """
        return self._bai.get_all_cve_names(self.sha256)

    def get_all_licenses(self) -> List[License]:
        """Get all licenses.

        Returns:
            List[str]: A list of license objects.
        """
        return self._bai.get_all_licenses(self.sha256)

    def get_all_license_short_names(self) -> List[str]:
        """Get all license short names.

        Returns:
            List[str]: A list of license short names.
        """
        return self._bai.get_all_license_short_names(self.sha256)

    def get_all_ascii_strings(self) -> List[str]:
        """Get all ASCII strings.

        Returns:
            List[str]: A list of ASCII strings.
        """
        return self._bai.get_all_ascii_strings(self.sha256)

    def get_sca_result(self) -> List[Component]:
        """Get SCA result.

        Returns:
            List[Component]: A list of sortware components.
        """
        return self._bai.get_sca_result(self.sha256)

    def get_overview(self) -> Dict[str, str]:
        """Fetch analysis overview.

        Returns:
            Dict[str, str]: A key-value pair containing overview of the file
        """
        return self._bai.get_overview(self.sha256)

    def list_func_offset(self) -> List[int]:
        """Fetch offsets of functions.

        Returns:
            List[int]: A list of function offsets
        """
        return self._bai.list_func_offset(self.sha256)

    def list_funcs(self) -> Iterator[Function]:
        """Parses the list of functions and returns a Function instance
        containing the given function's name, fileoffset, bytes, pseudocode
        and returns the list with a generator.

        Returns:
            Iterator[Function]: A Function iterator
        """
        return self._bai.list_funcs(self.sha256)

    def get_func_info(self, offset: int, with_embedding: bool = False) -> Function:
        """Fetch detailed information about the given function
        identified by its offset address.

        Params:
            offset: Offset address of desired function
            with_embedding: if True, try get the embedding representation of each function.

        Returns:
            Function: A Function instance containing the given function's
            name, fileoffset, bytes, pseudocode
        """
        return self._bai.get_func_info(self.sha256, offset, with_embedding)

    def get_funcs_info(self, offset: List[int], with_embedding: bool = False) -> Iterator[Function]:
        """Fetch detailed information about the given functions
        identified by its offset address.

        Params:
            offset: List of offset address of desired function
            with_embedding: if True, try get the embedding representation of each function.

        Returns:
            Iterator[Function]: A iterator Functions instance containing the given
            function's name, fileoffset, bytes, pseudocode.
        """
        return self._bai.get_funcs_info(self.sha256, offset, with_embedding)

    def get_func_match(self, offset: int) -> List[MatchedFunction]:
        """Match functions about the given function identified
        by its offset address.

        Params:
            offset: Offset address of desired function

        Returns:
            List[MatchedFunction]: a List containing 10 match results,
            every result is a Dict the contains score and pseudocode.
            The List is sorted by score from high to low.
        """
        return self._bai.get_func_match(self.sha256, offset)
