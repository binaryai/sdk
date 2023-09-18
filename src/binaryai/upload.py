import hashlib
import logging
import os
from typing import Dict, Optional

import requests
from gql import Client, gql
from gql.transport.exceptions import TransportQueryError

from binaryai.exceptions import FileRequiredError
from binaryai.query import MUTATION_CREATE_TICKET, MUTATON_CREATE_FILE
from binaryai.utils import sha256sum

logger = logging.getLogger(__name__)


class Uploader(object):
    """
    Uploads a file to server. See `binaryai.BinaryAI.upload` for detail.
    """

    def __init__(
        self,
        client: Client,
        *,
        filepath: Optional[str] = None,
        mem: Optional[bytes] = None,
        hooks: Optional[Dict] = None,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
    ) -> None:
        """
        Initialize an uploader instance. Detail usage are listed in `binaryai.BinaryAI.upload`.

        Params:
            client: gql Client
        """
        self._client = client
        self._hooks: Dict = hooks or {}

        self._sha256 = sha256
        self._md5 = md5 if not self._sha256 else None

        self._filename: Optional[str] = None
        self._filepath = filepath
        self._mem = mem

        if filepath and mem:
            raise ValueError("providing both filepath and mem is nonsense")

        if filepath:
            if not self._filename:
                self._filename = os.path.split(self._filepath)[-1]
            self._sha256 = sha256sum(filepath)
            self._md5 = None
        elif mem:
            self._sha256 = hashlib.sha256(self._mem).hexdigest()
            self._md5 = None

        if not self._sha256 and not self._md5:
            raise ValueError("no info provided, at least have one meaningful value")

    def upload(self) -> str:
        """
        Starts the upload sequence.

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
        """
        ticket = self.__create_ticket(filename=self._filename, sha256=self._sha256, md5=self._md5)
        ticket_type = ticket.get("__typename")

        if ticket_type == "File":
            return ticket["sha256"]

        reply_pos = None

        if ticket_type == "OwnershipTicket":
            logger.info("calculate pos")
            reply_pos = self.__reply_ticket_pos(ticket)
        elif ticket_type == "UploadTicket":
            logger.info("uploading file")
            self.__reply_ticket_upload(ticket)
        else:
            raise ValueError("unknown upload type, upgrade SDK or contact developers")

        ticket_id = ticket.get("ticketID")
        logger.info("creating file")
        verify_response = self.__verify_ticket(ticket_id, reply_pos=reply_pos)

        return verify_response["sha256"]

    def __create_ticket(
        self, *, filename: Optional[str] = None, sha256: Optional[str] = None, md5: Optional[str] = None
    ):
        """
        Checks if file exists on FileManager with filename and file's hashsum.

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
        """
        variables = {"input": {"name": filename, "sha256": sha256, "md5": md5}}
        data = gql(MUTATION_CREATE_TICKET)
        try:
            response = self._client.execute(data, variable_values=variables)
        except TransportQueryError as err:
            # If only md5 is provided, the error is hash missing
            is_hash_missing = False
            if err.errors:
                for e in err.errors:
                    if isinstance(e, dict):
                        if "No hash provided" in e.get("message", ""):
                            is_hash_missing = True
            if is_hash_missing:
                raise FileRequiredError("File upload need a file to continue") from None
            raise

        return response.get("createUploadTicket", {})

    def __reply_ticket_pos(self, ticket: Dict):
        """
        Calculate the POS argument
        """
        assert ticket["__typename"] == "OwnershipTicket"
        secret_prepend = ticket.get("secretPrepend")
        secret_append = ticket.get("secretAppend")
        assert secret_prepend and secret_append
        if not self._filepath and not self._mem:
            raise FileRequiredError("PoS verify need a file to continue")

        hasher = hashlib.sha256()
        hasher.update(secret_prepend.encode())
        if self._mem:
            hasher.update(self._mem)
        else:
            with open(self._filepath, "rb", buffering=0) as upload_file:
                file_size = upload_file.seek(0, os.SEEK_END)
                upload_file.seek(0, os.SEEK_SET)
                if file_size < 16:
                    hasher.update(b"\x04" * min(16 - file_size, 8))
                while True:
                    chunk = upload_file.read(hasher.block_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
                if file_size < 8:
                    hasher.update(b"\x95" * min(8 - file_size, 8))
        hasher.update(secret_append.encode())
        return hasher.hexdigest().lower()

    def __reply_ticket_upload(self, ticket: dict):
        """
        Uploads file to FileManager.

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
        """
        assert ticket["__typename"] == "UploadTicket"
        if not self._filepath and not self._mem:
            raise FileRequiredError("File upload need a file to continue")

        if self._hooks.get("upload_ticket"):
            ticket = self._hooks["upload_ticket"](ticket)
        auth_header = {kv["key"]: kv["value"] for kv in ticket.get("requestHeaders", [])}

        with requests.Session() as session:
            if self._mem:
                session.put(url=ticket["url"], headers=auth_header, data=self._mem)
            else:
                with open(self._filepath, "rb") as upload_file:
                    session.put(url=ticket["url"], headers=auth_header, data=upload_file)

    def __verify_ticket(self, ticket_id: str, *, reply_pos: Optional[str] = None):
        """
        Registers uploaded file on BinaryAI service.

        Raises:
            BinaryAIGQLError: if the GraphQL endpoints returns errors.
        """
        variables = {
            "input": {
                "ticketID": ticket_id,
            }
        }
        if reply_pos:
            variables["input"]["ownershipPoS"] = reply_pos
        data = gql(MUTATON_CREATE_FILE)
        return self._client.execute(data, variable_values=variables)["createFile"]
