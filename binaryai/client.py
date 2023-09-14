#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
import os
import threading
import time
from typing import Dict, Iterator, List, Optional, Union
from urllib.parse import urlparse

from deprecated import deprecated
from gql import Client, gql
from gql.transport import Transport
from gql.transport.exceptions import TransportQueryError
from gql.transport.requests import RequestsHTTPTransport
from qcloud_requests_auth.qcloud_auth import QCloudRequestsAuth
from requests.auth import AuthBase

from binaryai.component import Component
from binaryai.compressed_file import CompressedFile
from binaryai.cve import CVE
from binaryai.exceptions import BinaryAIGQLError, BinaryAIResponseError, FileNotExistError
from binaryai.function import Function, MatchedFunction
from binaryai.license import License
from binaryai.query import (
    MUTATION_REANALYZE,
    QUERY_ASCII_STRING,
    QUERY_CHECK_STATE,
    QUERY_COMPRESSED_FILE,
    QUERY_CVE_NAME,
    QUERY_DOWNLOAD_LINK,
    QUERY_FILE_SIZE,
    QUERY_FILENAMES,
    QUERY_FUNCTION_INFO,
    QUERY_FUNCTION_LIST,
    QUERY_FUNCTION_MATCH,
    QUERY_FUNCTIONS_INFO,
    QUERY_LICENSE,
    QUERY_LICENSE_SHORT_NAME,
    QUERY_MIME_TYPE,
    QUERY_OVERVIEW,
    QUERY_SCA,
    QUERY_SHA256,
)
from binaryai.upload import Uploader
from binaryai.utils import get_result

# Default constance SDK name string
DEFAULT_SDK_NAME = "PythonSDK"

# Default interval in seconds for polling GraphQL endpoint
DEFAULT_POLL_INTERVAL = 2

# Default timeout in seconds for polling GraphQL endpoint
DEFAULT_POLL_TIMEOUT = 60

# A request source header map
HEADER_REQUEST_SOURCE = {"x-request-tags": DEFAULT_SDK_NAME}

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
        transport: Transport = None,
        poll_timeout: int = DEFAULT_POLL_TIMEOUT,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        secret_id: Optional[str] = os.environ.get("BINARYAI_SECRET_ID"),
        secret_key: Optional[str] = os.environ.get("BINARYAI_SECRET_KEY"),
        auth: Optional[AuthBase] = None,
        endpoint: str = DEFAULT_ENDPOINT,
    ) -> None:
        super().__init__()
        if secret_id is None or secret_key is None:
            raise ValueError("Please set secret id and key in your code or environ")
        if not transport:
            transport = RequestsHTTPTransport(
                url=endpoint,
                headers=HEADER_REQUEST_SOURCE,
                verify=True,
                retries=3,
            )
        if auth is None:
            transport.auth = QCloudRequestsAuth(
                secret_id,
                secret_key,
                urlparse(transport.url).netloc,  # netloc is real host header
                "ap-shanghai",
                "binaryai",
                "BinaryAI",
                "2023-04-15",
            )
        else:
            transport.auth = auth
        if transport.headers is None:
            transport.headers = HEADER_REQUEST_SOURCE
        else:
            transport.headers.update(HEADER_REQUEST_SOURCE)

        self._transport = transport
        self._client = Client(transport=transport, fetch_schema_from_transport=True)
        self._poll_timeout = int(poll_timeout)
        self._poll_interval = int(poll_interval)
        self._logger = logging.getLogger(__name__)

    def _execute_gql_sync(self, *args, **kwargs):
        try:
            return self._client.execute(*args, **kwargs)
        except TransportQueryError as e:
            raise BinaryAIGQLError(self._transport.response_headers.get("x-trace-id"), e.errors)

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
        Raises:
            BinaryAIGQLError: An error that GraphQL endpoint could possibly returns to show anything went wrong.
            FileRequiredError: Only hash is provided but file is necessary. If a file is not provided, future request
                is not possible.
        """
        uploader = Uploader(self._client, filepath=filepath, mem=mem, hooks=hooks, sha256=sha256, md5=md5)
        return uploader.upload()

    def _reanalyze(self, sha256: str):
        """Reanalyze target file.

        Args:
            sha256: File sha256sum.

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
        """
        variables = {
            "sha256": sha256,
        }
        data = gql(MUTATION_REANALYZE)
        return self._execute_gql_sync(data, variable_values={"input": variables})

    def _poll_status_ready_storm(self, sha256: str) -> None:
        """Polls analysis status.

        Args:
            sha256: File sha256sum.

        Raise:
            TimeoutError: An error occur when polling timeout
        """
        start = time.time()
        analysis_ok = False
        while time.time() - start < self._poll_timeout:
            analysis_ok = False
            response = self._get_file(sha256)
            if response["file"] is None:
                raise FileNotExistError("File is not existed")
            analyzeStatus = response["file"]["smartBinaryStatus"]
            status = None if analyzeStatus is None else analyzeStatus["status"]
            if status == "Success":
                analysis_ok = True
                break
            elif status in ("Fail", "Timeout"):
                analysis_ok = False
                break
            elif status in ("Ready", "Waiting", "Running"):
                pass
            else:
                raise BinaryAIResponseError(f"Unknown SmartBinary analyzeStatus: {status}")

            self._logger.debug("=")
            time.sleep(self._poll_interval)
        if not analysis_ok:
            raise TimeoutError

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
            resp: dict
            resp = self._reanalyze(sha256).get("reanalyze")
            if not resp:
                raise FileNotExistError("File not found")
            reason = resp.get("noopReason")
            if not reason:
                self._logger.info("noopReason does not exist, seems a new analysis started")
            elif reason in ["WouldNotChange", "RateLimited"]:
                self._logger.info("noopReason is {}, consider as done".format(reason))
                break
            else:
                self._logger.info("noopReason is {}, seems still running".format(reason))
            sleeper.wait(interval)
        else:
            raise TimeoutError("analysis still not in finished result after timeout")

    @deprecated()
    def analyze(
        self,
        sha256: str,
        force: bool = False,
        short_wait_for: bool = True,
        long_wait_for: bool = False,
    ):
        """Ask server to analyze a file identified by sha256, and polls
        for status until analysis is complete or an error occurs.

        .. note:: This function is now deprecated and only works as an example of showing
                  how to wait some certain analyzers. To wait for a file's result, use
                  new function `wait_until_analysis_done`. It works better and have more
                  reasonable check.

        Args:
            sha256: File sha256sum.
            force: A boolean to force server or not to (re)analyze the
                   given file. If force is False, server will return results
                   if any without analyzing it, or do analyze when server has
                   no results at all. If force is True, then server will
                   analyze the file from the very beginning whatsoever.
            short_wait_for: Wait for a while on those simple analysis to complete,
                   so that we can retrieve some information as soon as possible, e.g.
                   executable info and sca info.
            long_wait_for: Wait for all analysis to complete, including those
                   long-time-consuming operations, e.g. decompiling.

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returned errors.
            TimeoutError: if the operation timed out
        """
        if not force:
            resp = self._get_file(sha256)
            if resp["file"] is None:
                raise FileNotExistError("File is not existed")
            analyzeStatus = resp["file"]["smartBinaryStatus"]
            if analyzeStatus is None or analyzeStatus["status"] == "Ready":
                self._reanalyze(sha256)
        else:
            self._reanalyze(sha256)

        self._logger.info("started analysis")
        if long_wait_for:
            self._poll_status_ready_storm(sha256)
            self._poll_status_ready_beat(sha256)
        elif short_wait_for:
            self._poll_status_ready_storm(sha256)
        self._logger.info("completed analysis")

    def get_analyze_status(self, sha256: str) -> Dict:
        """Return current state of each analyzers. Read API document about relationship between analyzer and results.

        Args:
            sha256: File sha256sum.

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returned errors.
            TimeoutError: if the operation timed out
        """
        resp = self._get_analyze_status(sha256).get("file")
        if resp is None:
            raise FileNotExistError("File not exists, or never analyzed")
        return {
            "smartBinary": resp.get("smartBinaryStatus", {}).get("status"),
            "smartBeat": resp.get("smartBeatStatus", {}).get("status"),
        }

    def get_sha256(self, md5: str) -> str:
        """Get file sha256 by its md5.

        Args:
            md5: File md5 hash.

        Returns:
            str: File sha256sum.
        """
        vars = {"md5": md5}
        data = gql(QUERY_SHA256)
        resp = self._client.execute(data, variable_values=vars)
        return get_result(resp, ["file", "sha256"])

    def get_filenames(self, sha256: str) -> List[str]:
        """Get all uploaded filenames for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[str]: A list of filenames.
        """
        vars = {"sha256": sha256}
        data = gql(QUERY_FILENAMES)
        resp = self._execute_gql_sync(data, variable_values=vars)
        return get_result(resp, ["file", "name"])

    def get_mime_type(self, sha256: str) -> str:
        """Get MIME type for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            str: MIME type string.
        """
        vars = {"sha256": sha256}
        data = gql(QUERY_MIME_TYPE)
        resp = self._execute_gql_sync(data, variable_values=vars)
        return get_result(resp, ["file", "mimeType"])

    def get_size(self, sha256: str) -> int:
        """Get size in bytes of a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            int: File size in bytes.
        """
        vars = {"sha256": sha256}
        data = gql(QUERY_FILE_SIZE)
        resp = self._execute_gql_sync(data, variable_values=vars)
        return get_result(resp, ["file", "size"])

    def get_compressed_files(self, sha256: str) -> List[CompressedFile]:
        """Get a list of files inside a compressed file identified by a sha256.

        Args:
                sha256: File sha256sum.

         Returns:
                int: File size in bytes.

         Raises:
                BinaryAIGQLError: if the GraphQL endpoints returns errors.
                BinaryAIResponseError: if the GraphQL endpoints
                returns unparsable data.
        """
        variables = {"sha256": sha256}
        data = gql(QUERY_COMPRESSED_FILE)

        resp = self._execute_gql_sync(data, variable_values=variables)
        compressed_files = get_result(resp, ["file", "decompressed"])

        file_list = []
        for compressed_file in compressed_files or []:
            if compressed_file:
                file_list.append(
                    CompressedFile(
                        path=compressed_file.get("path"),
                        sha256=compressed_file.get("sha256"),
                    )
                )
        return file_list

    def get_all_cves(self, sha256: str) -> List[CVE]:
        """Get all CVEs for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[str]: A list of CVE string.
        """
        vars = {"sha256": sha256}
        data = gql(QUERY_CVE_NAME)

        resp = self._execute_gql_sync(data, variable_values=vars)
        scainfo = get_result(resp, ["file", "scainfo"])

        cve_list = []
        for elem in scainfo or []:
            for mapping in elem["cves"] or []:
                cve_name = mapping["name"]
                if cve_name:
                    cve_list.append(CVE(name=cve_name))
        return cve_list

    def get_all_cve_names(self, sha256: str) -> List[str]:
        """Get all CVE names for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[str]: A list of CVE names.
        """
        vars = {"sha256": sha256}
        data = gql(QUERY_CVE_NAME)

        resp = self._execute_gql_sync(data, variable_values=vars)
        scainfo = get_result(resp, ["file", "scainfo"])

        cve_list = []
        for elem in scainfo or []:
            for mapping in elem["cves"] or []:
                cve_name = mapping["name"]
                if cve_name:
                    cve_list.append(cve_name)
        return cve_list

    def get_all_licenses(self, sha256: str) -> List[License]:
        """Get all licenses for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[str]: A list of license string.
        """
        vars = {"sha256": sha256}
        data = gql(QUERY_LICENSE)

        resp = self._execute_gql_sync(data, variable_values=vars)
        scainfo = get_result(resp, ["file", "scainfo"])

        license_list = []
        for mapping in scainfo or []:
            array = mapping.get("licenselist")
            for item in array or []:
                d = {
                    "full_name": item.get("fullName"),
                    "short_name": item.get("shortName"),
                    "content": item.get("content"),
                    "risk": item.get("risk"),
                    "tags": item.get("tags"),
                    "source": item.get("source"),
                    "url": item.get("url"),
                    "extra": item.get("extra"),
                    "is_pass": item.get("pass"),
                    "check_reason": item.get("checkreason"),
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
        vars = {"sha256": sha256}
        data = gql(QUERY_LICENSE_SHORT_NAME)

        resp = self._execute_gql_sync(data, variable_values=vars)
        scainfo = get_result(resp, ["file", "scainfo"])

        license_list = []
        for elem in scainfo or []:
            # value of "license" is a string joined by comma
            license_short_names = elem["license"]
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
        vars = {"sha256": sha256}
        data = gql(QUERY_ASCII_STRING)

        resp = self._execute_gql_sync(data, variable_values=vars)
        executable = get_result(resp, ["file", "executable"])

        if executable and "asciiStrings" in executable:
            return executable["asciiStrings"]
        else:
            return []

    def get_sca_result(self, sha256: str) -> List[Component]:
        """Get SCA result for a given file.

        Args:
            sha256: File sha256sum.

        Returns:
            List[Component]: A list of software components.
        """
        vars = {"sha256": sha256}
        data = gql(QUERY_SCA)

        resp = self._execute_gql_sync(data, variable_values=vars)
        scainfo = get_result(resp, ["file", "scainfo"])

        component_list = []
        for elem in scainfo or []:
            component_list.append(
                Component(
                    name=elem.get("name"),
                    version=elem.get("version"),
                    description=elem.get("description"),
                    source_code_url=elem.get("sourceCodeURL"),
                    summary=elem.get("summary"),
                )
            )
        return component_list

    def _get_analyze_status(self, sha256: str) -> Dict:
        vars = {"sha256": sha256}
        data = gql(QUERY_CHECK_STATE)
        return self._execute_gql_sync(data, variable_values=vars)

    def _poll_status_ready_beat(self, sha256: str) -> bool:
        start = time.time()
        analysis_ok = False
        while time.time() - start < self._poll_timeout:
            analysis_ok = False
            response = self._get_file(sha256)
            if response["file"] is None:
                raise FileNotExistError("File is not existed")
            analyzeStatus = response["file"]["smartBeatStatus"]
            status = None if analyzeStatus is None else analyzeStatus["status"]
            if status == "Success":
                analysis_ok = True
                break
            elif status in ("Fail", "Timeout"):
                analysis_ok = False
                break
            elif status in ("Ready", "Waiting", "Running"):
                pass
            else:
                raise BinaryAIResponseError(f"Unknown SmartBeat analyzeStatus: {status}")

            self._logger.debug("=")
            time.sleep(self._poll_interval)
        return analysis_ok

    def get_overview(self, sha256: str) -> Dict[str, Union[str, int]]:
        """Fetch analysis overview from BinaryAI Beat server by file's sha256.

        Returns:
            A key-value pair containing overview of the binary file

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
        """
        variables = {"sha256": sha256}
        data = gql(QUERY_OVERVIEW)
        resp = self._execute_gql_sync(data, variable_values=variables)
        basicInfo = get_result(resp, ["file", "decompileResult", "basicInfo"])

        return (
            {
                "fileType": basicInfo["fileType"],
                "machine": basicInfo["machine"],
                "platform": basicInfo["platform"],
                "endian": basicInfo["endian"],
                "loader": basicInfo["loader"],
                "entryPoint": int(basicInfo["entryPoint"]),
                "baseAddress": int(basicInfo["baseAddress"]),
            }
            if basicInfo
            else {}
        )

    def get_download_link(self, sha256: str) -> Optional[str]:
        """Fetch file download link by file's sha256.

        Returns:
            A link can be used to download link later. The link might expire.

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
        """
        variables = {"sha256": sha256}
        data = gql(QUERY_DOWNLOAD_LINK)
        resp = self._execute_gql_sync(data, variable_values=variables)
        if resp.get("file") is None:
            raise FileNotExistError("File not exists")

        lnk = get_result(resp, ["file", "downloadLink"])
        if not isinstance(lnk, str):
            return None
        if len(lnk) == 0:
            return None
        return lnk

    def list_func_offset(self, sha256: str) -> List[int]:
        """Fetch offsets of functions from analysis.

        Returns:
            list of function offset
        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
        """
        vars = {"sha256": sha256}
        data = gql(QUERY_FUNCTION_LIST)
        resp = self._client.execute(data, variable_values=vars)
        func_list = get_result(resp, ["file", "decompileResult", "functions"])

        offset_list = []
        for func in func_list or []:
            offset_list.append(int(func["offset"]))
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

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
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

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
            BinaryAIResponseError: if the GraphQL endpoints
                returns unparsable data.
        """
        vars = {"sha256": sha256, "offset": str(offset), "withEmbedding": with_embedding}
        data = gql(QUERY_FUNCTION_INFO)
        resp = self._execute_gql_sync(data, variable_values=vars)
        func = get_result(resp, ["file", "decompileResult", "function"])

        return (
            Function(
                func["name"],
                int(func["offset"]),
                func.get("pseudoCode", {}).get("code", None),
                func.get("embedding", {}).get("vector", None),
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
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
            BinaryAIResponseError: if the GraphQL endpoints
                returns unparsable data.
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
            vars = {"sha256": sha256, "offset": offsets[i : i + step], "withEmbedding": with_embedding}
            data = gql(QUERY_FUNCTIONS_INFO)
            resp = self._execute_gql_sync(data, variable_values=vars)
            funcs = get_result(resp, ["file", "decompileResult", "functions"])
            if not funcs:
                return []
            yield from [
                Function(
                    func["name"],
                    int(func["offset"]),
                    func.get("pseudoCode", {}).get("code", None),
                    func.get("embedding", {}).get("vector", None),
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

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
            BinaryAIResponseError: if the GraphQL endpoints
                returns unparsable data
        """
        vars = {"sha256": sha256, "offset": str(offset)}
        data = gql(QUERY_FUNCTION_MATCH)
        resp = self._execute_gql_sync(data, variable_values=vars)
        func = get_result(resp, ["file", "decompileResult", "function"])
        if not func:
            return []

        matched_func_list = []
        for item in func.get("match", []):
            matched_func = MatchedFunction(
                score=item.get("score"),
                code=item.get("function", {}).get("code"),
            )
            matched_func_list.append(matched_func)
        return matched_func_list
