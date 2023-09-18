import hashlib
import logging
import os
from typing import Dict, Optional

import httpx

from binaryai import client_stub
from binaryai.exceptions import FileRequiredError
from binaryai.utils import sha256sum

logger = logging.getLogger(__name__)


class Uploader(object):
    """
    Uploads a file to server. See `binaryai.BinaryAI.upload` for detail.
    """

    def __init__(
        self,
        client: client_stub.Client,
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
        """
        ticket = self.__create_ticket(filename=self._filename, sha256=self._sha256, md5=self._md5)
        ticket_type = ticket.typename__

        if ticket_type == "File":
            return ticket.sha256

        reply_pos = None

        if ticket_type == "OwnershipTicket":
            logger.info("calculate pos")
            reply_pos = self.__reply_ticket_pos(ticket)
        elif ticket_type == "UploadTicket":
            logger.info("uploading file")
            self.__reply_ticket_upload(ticket)
        else:
            raise ValueError("unknown upload type, upgrade SDK or contact developers")

        ticket_id = ticket.ticket_i_d
        logger.info("creating file")
        req = client_stub.CreateFileInput(ticketID=ticket_id, ownershipPoS=reply_pos)
        verify_response = self._client.create_file(req)

        return verify_response.create_file.sha256

    def __create_ticket(
        self, *, filename: Optional[str] = None, sha256: Optional[str] = None, md5: Optional[str] = None
    ):
        """
        Checks if file exists on FileManager with filename and file's hashsum.
        """
        req = client_stub.CreateUploadTicketInput(name=filename, sha256=sha256, md5=md5)
        try:
            response = self._client.check_or_upload(req)
        except client_stub.GraphQLClientGraphQLMultiError as err:
            # If only md5 is provided, the error is hash missing
            is_hash_missing = False
            for e in err.errors:
                if "No hash provided" in e.message:
                    is_hash_missing = True
                    break
            if is_hash_missing:
                raise FileRequiredError("File upload need a file to continue") from None
            raise

        return response.create_upload_ticket

    def __reply_ticket_pos(self, ticket: client_stub.CheckOrUploadCreateUploadTicketOwnershipTicket):
        """
        Calculate the POS argument
        """
        assert ticket.typename__ == "OwnershipTicket"
        secret_prepend = ticket.secret_prepend
        secret_append = ticket.secret_append
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

    def __reply_ticket_upload(self, ticket: client_stub.CheckOrUploadCreateUploadTicketUploadTicket):
        """
        Uploads file to FileManager.
        """
        assert ticket.typename__ == "UploadTicket"
        if not self._filepath and not self._mem:
            raise FileRequiredError("File upload need a file to continue")

        if self._hooks.get("upload_ticket"):
            ticket = self._hooks["upload_ticket"](ticket)
        auth_header = {kv.key: kv.value for kv in ticket.request_headers}

        with httpx.Client() as upload_client:
            if self._mem:
                upload_client.put(url=ticket.url, headers=auth_header, content=self._mem)
            else:
                with open(self._filepath, "rb") as upload_file:
                    upload_client.put(url=ticket.url, headers=auth_header, content=upload_file)
