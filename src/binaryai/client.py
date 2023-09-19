#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import os
import threading
import time
from importlib.metadata import version
from typing import Dict, Iterator, List, Optional, Union
from urllib.parse import urlparse

import httpx

from binaryai import client_stub
from binaryai.component import Component
from binaryai.compressed_file import CompressedFile
from binaryai.exceptions import FileNotExistError
from binaryai.function import Function, MatchedFunction
from binaryai.license import License
from binaryai.upload import Uploader
from binaryai.utils import QCloudHttpxAuth

SDK_VERSION = version("binaryai")

# Default constance SDK name string
DEFAULT_SDK_NAME = "PythonSDK"

# Default interval in seconds for polling GraphQL endpoint
DEFAULT_POLL_INTERVAL = 2

# Default timeout in seconds for polling GraphQL endpoint
DEFAULT_POLL_TIMEOUT = 60

# A request source header map
HEADER_REQUEST_SOURCE = {
    "x-request-tags": DEFAULT_SDK_NAME,
    "user-agent": f"python-httpx/{httpx.__version__} (python; {DEFAULT_SDK_NAME}/{SDK_VERSION})",
}

# Default GraphQL transport
DEFAULT_ENDPOINT = "https://api.binaryai.cn/v1/endpoint"

# Default license list separator
DEFAULT_LICENSE_SEPARATOR = ","


class BinaryAI(object):
    """BinaryAI client used to interact with servers.
    Users can receive upload, do analysis, and receive the detailed results
    by using this client.
    Note:
        Since the transport session/connection under the hood will be use one
        at a time, this class is NOT THREAD SAFE.
    """

    def __init__(
        self,
        *,
        secret_id: Optional[str] = os.environ.get("BINARYAI_SECRET_ID"),
        secret_key: Optional[str] = os.environ.get("BINARYAI_SECRET_KEY"),
        endpoint: str = os.environ.get("BINARYAI_ENDPOINT", DEFAULT_ENDPOINT),
    ) -> None:
        super().__init__()
        if secret_id is None or secret_key is None:
            raise ValueError("Please set secret id and key in your code or environ")
        transport = httpx.HTTPTransport(
            verify=True,
            retries=3,
        )
        auth = QCloudHttpxAuth(
            secret_id,
            secret_key,
            urlparse(endpoint).netloc,  # netloc is real host header
            "ap-shanghai",
            "binaryai",
            "BinaryAI",
            "2023-04-15",
        )
        self._http_client = httpx.Client(auth=auth, transport=transport, headers=HEADER_REQUEST_SOURCE)
        self._client = client_stub.Client(url=endpoint, http_client=self._http_client)
        self._logger = logging.getLogger(__name__)

    def upload(
        self,
        filepath: Optional[str] = None,
        *,
        mem: Optional[bytes] = None,
        hooks: Optional[Dict] = None,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
    ) -> str:
        """Uploads a file to server.

        At least one of following input should be not None:
        * File upload: fill `filepath` for the file to be upload on the disk
        * Memory upload: `mem` for the file to be upload in the memory

        If you only have the hash, you can try to fill `sha256` and `md5`, but the error FileRequiredError might be
        raised. Hash is ignored if file is already provided through `filepath` or `mem. When multiple hashes
        provided, only use sha256.

        Memory upload, hash upload and `hooks` are experimental features. They might be changed without noticed.

        Args:
            filepath(Optional): A pathname to a given file for file upload.
            mem(Optional): A byte buffer for a file in memory to be upload.
            hooks(Optional): A dict to modify arguments before certain operations.
            sha256(Optional): A string for hash upload.
            md5(Optional): A string for hash upload.
        Returns:
            A actual sha256 that server calculates and returns.
        """
        uploader = Uploader(self._client, filepath=filepath, mem=mem, hooks=hooks, sha256=sha256, md5=md5)
        return uploader.upload()

    def _reanalyze(self, sha256: str):
        """Reanalyze target file.

        Args:
            sha256: File sha256sum.
        """
        req = client_stub.ReanalyzeInput(sha256=sha256)
        return self._client.reanalyze(req).reanalyze

    def wait_until_analysis_done(
        self,
        sha256: str,
        timeout: int = DEFAULT_POLL_TIMEOUT,
        interval: int = DEFAULT_POLL_INTERVAL,
    ):
        """Wait until having a latest stable result, by waiting for if all analysis on this file
        done. You can set the wait timeout in seconds. If no stable results available after
        timeout, a TimeoutError is raised.

        If parts being waitied are failed instead of succeed, this function will *not* raise
        any exception. To get detailed info about status, call `get_analyze_status`.

        For analyze in parallel, consider call this function in a seperate thread, since this
        function is wait by calling `threaing.Event`. This function's implementation is a good
        reference of judging if a file is finished analyzing.

        Args:
            sha256: File sha256 sum.
            timeout(int): maxium wait time in seconds. If negative, wait forever.
            interval(int): pool interval in seconds. Raise error if not positive.
        """
        if interval <= 0:
            raise ValueError("interval should be positive")
        # TODO: We want a new mutation method, which works like auto reanalyze, and also return
        # if a new analyze is started. For now, we use fields in query to trigger it. The new
        # method can avoid waiting by counting succeed results and make implementation more elegant.
        # The new method can be provided in future versions by changing behaviour of `reanalyze`.

        sleeper = threading.Event()
        wait_since = time.time()
        while timeout < 0 or (time.time() - wait_since) < timeout:
            resp = self._reanalyze(sha256)
            if not resp:
                raise FileNotExistError("File not found")
            reason = resp.noop_reason
            if not reason:
                self._logger.info("noopReason does not exist, seems a new analysis started")
            elif reason in [client_stub.NoopReason.WouldNotChange, client_stub.NoopReason.RateLimited]:
                self._logger.info("noopReason is {}, consider as done".format(reason))
                break
            else:
                self._logger.info("noopReason is {}, seems still running".format(reason))
            sleeper.wait(interval)
        else:
            raise TimeoutError("analysis still not in finished result after timeout")

    def get_analyze_status(self, sha256: str) -> Dict:
        """Return current state of each analyzers. Read API document about relationship between analyzer and results.

        Args:
            sha256: File sha256sum.
        """
        resp = self._client.check_state(sha256).file
        if resp is None:
            raise FileNotExistError("File not exists, or never analyzed")
        beatStatus = None
        if resp.smart_beat_status:
            beatStatus = resp.smart_beat_status.status
        binaryStatus = None
        if resp.smart_binary_status:
            binaryStatus = resp.smart_binary_status.status
        return {
            "smartBinary": binaryStatus,
            "smartBeat": beatStatus,
        }

    def get_sha256(self, md5: str) -> str:
        """Get file sha256 by its md5.

        Args:
            md5: File md5 hash.

        Returns:
            str: File sha256sum.
        """
        f = self._client.sha256(md5).file
        if not f:
            raise FileNotExistError("File not exists or no permission")
        return f.sha256

    def get_filenames(self, sha256: str) -> List[str]:
        """Get all uploaded filenames for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[str]: A list of filenames.
        """
        f = self._client.filename(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")
        return f.name

    def get_mime_type(self, sha256: str) -> str:
        """Get MIME type for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            str: MIME type string.
        """
        f = self._client.m_i_m_e_type(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")
        return f.mime_type

    def get_size(self, sha256: str) -> int:
        """Get size in bytes of a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            int: File size in bytes.
        """
        f = self._client.file_size(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")
        return f.size

    def get_compressed_files(self, sha256: str) -> List[CompressedFile]:
        """Get a list of files inside a compressed file identified by a sha256.

        Args:
                sha256: File sha256sum.

         Returns:
                int: File size in bytes.
        """
        f = self._client.compressed_file(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")

        file_list = []
        for compressed_file in f.decompressed or []:
            if compressed_file:
                file_list.append(
                    CompressedFile(
                        path=compressed_file.path,
                        sha256=compressed_file.sha256,
                    )
                )
        return file_list

    def get_all_cve_names(self, sha256: str) -> List[str]:
        """Get all CVE names for a given file.

        Args:
            sha256: File sha256sum.
        """
        f = self._client.c_v_e_name(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")

        cve_list = []
        for elem in f.scainfo or []:
            for mapping in elem.cves or []:
                cve_list.append(mapping.name)
        return cve_list

    def get_all_licenses(self, sha256: str) -> List[License]:
        """Get all licenses for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[str]: A list of license string.
        """
        f = self._client.license(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")

        license_list = []
        for mapping in f.scainfo or []:
            for item in mapping.licenselist or []:
                d = {
                    "full_name": item.full_name,
                    "short_name": item.short_name,
                    "content": item.content,
                    "risk": item.risk,
                    "tags": item.tags,
                    "source": item.source,
                    "url": item.url,
                    "extra": item.extra,
                    "is_pass": item.pass_,
                    "check_reason": item.checkreason,
                }
                license_list.append(License(**d))
        return license_list

    def get_all_license_short_names(self, sha256: str) -> List[str]:
        """Get all license short names for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[str]: A list of license short names.
        """
        f = self._client.license_short_name(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")

        license_list = []
        for elem in f.scainfo or []:
            # value of "license" is a string joined by comma
            license_short_names = elem.license
            if license_short_names:
                license_list.extend(license_short_names.split(DEFAULT_LICENSE_SEPARATOR))
        return license_list

    def get_all_ascii_strings(self, sha256: str) -> List[str]:
        """Get all ASCII strings for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[str]: A list of ASCII strings.
        """
        f = self._client.a_s_c_i_i_string(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")

        if f.executable and f.executable.ascii_strings:
            return f.executable.ascii_strings
        else:
            return []

    def get_sca_result(self, sha256: str) -> List[Component]:
        """Get SCA result for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[Component]: A list of software components.
        """
        f = self._client.s_c_a(sha256).file
        if not f:
            raise FileNotExistError("File not exists or no permission")

        component_list = []
        for elem in f.scainfo or []:
            component_list.append(
                Component(
                    name=elem.name,
                    version=elem.version,
                    description=elem.description,
                    source_code_url=elem.source_code_u_r_l,
                    summary=elem.summary,
                )
            )
        return component_list

    def get_overview(self, sha256: str) -> Dict[str, Union[str, int]]:
        """Fetch analysis overview from BinaryAI Beat server by file's sha256.

        Returns:
            A key-value pair containing overview of the binary file
        """
        f = self._client.overview(sha256).file
        if not f:
            raise FileNotExistError("File not exists")
        if not f.decompile_result:
            return {}
        basicInfo = f.decompile_result.basic_info

        return (
            {
                "fileType": basicInfo.file_type,
                "machine": basicInfo.machine,
                "platform": basicInfo.platform,
                "endian": basicInfo.endian,
                "loader": basicInfo.loader,
                "entryPoint": int(basicInfo.entry_point),
                "baseAddress": int(basicInfo.base_address),
            }
            if basicInfo
            else {}
        )

    def get_download_link(self, sha256: str) -> Optional[str]:
        """Fetch file download link by file's sha256.

        Returns:
            A link can be used to download link later. The link might expire.
        """
        f = self._client.download_link(sha256).file
        if not f:
            raise FileNotExistError("File not exists")

        lnk = f.download_link
        if not isinstance(lnk, str):
            return None
        if len(lnk) == 0:
            return None
        return lnk

    def list_func_offset(self, sha256: str) -> List[int]:
        """Fetch offsets of functions from analysis.

        Returns:
            list of function offset
        """
        f = self._client.function_list(sha256).file
        if not f:
            raise FileNotExistError("File not exists")
        decompileResult = f.decompile_result
        func_list = None if not decompileResult else decompileResult.functions

        offset_list = []
        for func in func_list or []:
            offset_list.append(int(func.offset))
        return offset_list

    def list_funcs(self, sha256: str, batch_size: int = 32) -> Iterator[Function]:
        """Parses the list of functions and returns a Function instance
        containing the given function's name, fileoffset, bytes, pseudocode
        and returns the list with a generator.

        Args:
            sha256: File sha256sum.
            batch_size: Batch size to get functions' info

        Returns:
            Function Iterator
        """
        offset_list = self.list_func_offset(sha256)
        self._logger.info("found {} functions".format(len(offset_list)))
        if not offset_list:
            return []
        if not batch_size or batch_size < 0:
            raise ValueError(f"invalid batch size: {batch_size}")
        yield from self._get_funcs_info(sha256, offset_list, batch_size)

    def get_func_info(self, sha256: str, offset: int, with_embedding: bool = False) -> Function:
        """Fetch detailed information about the given function
        identified by its offset address.

        Params:
            offset: offset address of desired function

        Returns:
            Function instance containing the given function's
            name, fileoffset, bytes, pseudocode
        """
        f = self._client.function_info(sha256, offset, with_embedding).file
        if not f:
            raise FileNotExistError("File not exists")
        decompileResult = f.decompile_result
        func = None if not decompileResult else decompileResult.function

        return (
            Function(
                func.name,
                int(func.offset),
                (None if not func.pseudo_code else func.pseudo_code.code),
                (None if not func.embedding else func.embedding.vector),
            )
            if func
            else None
        )

    def get_funcs_info(
        self, sha256: str, offsets: List[int], batch_size: int = 32, with_embedding: bool = False
    ) -> Iterator[Function]:
        """Fetch detailed information about the given functions
        identified by its offset address.

        Params:
            offsets: A list of offset addresses of desired functions
            batch_size: Batch size to get functions' info.

        Returns:
            Function iterator

        Raises:
            ValueError: invalid batch size
        """
        if not offsets:
            return []
        if not batch_size or batch_size < 0:
            raise ValueError(f"invalid batch size: {batch_size}")
        return self._get_funcs_info(sha256, offsets, batch_size, with_embedding)

    def _get_funcs_info(
        self, sha256: str, offsets: List[int], step: int = 32, with_embedding: bool = False
    ) -> Iterator[Function]:
        """Get functions' info in batches"""
        for i in range(0, len(offsets), step):
            f = self._client.functions_info(sha256, with_embedding, offsets[i : i + step]).file
            if not f:
                raise FileNotExistError("File not exists")
            decompileResult = f.decompile_result
            funcs = None if not decompileResult else decompileResult.functions
            if not funcs:
                return []

            yield from [
                Function(
                    func.name,
                    int(func.offset),
                    (None if not func.pseudo_code else func.pseudo_code.code),
                    (None if not func.embedding else func.embedding.vector),
                )
                for func in funcs
            ]

    def get_func_match(self, sha256: str, offset: int) -> List[MatchedFunction]:
        """Match functions about the given function identified
        by its offset address.

        Params:
            offset: offset address of desired function

        Returns:
            a List containing 10 match results, every result is a Dict
            the contains score and pseudocode. The List is sorted by
            score from high to low
        """
        f = self._client.function_match(sha256, offset).file
        if not f:
            raise FileNotExistError("File not exists")
        decompileResult = f.decompile_result
        func = None if not decompileResult else decompileResult.function
        if not func:
            return []

        matched_func_list = []
        for item in func.match:
            matched_func = MatchedFunction(
                score=item.score,
                code=(None if not item.function else item.function.code),
            )
            matched_func_list.append(matched_func)
        return matched_func_list
