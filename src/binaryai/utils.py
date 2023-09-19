#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import datetime
import hashlib
import hmac
import typing
from hashlib import sha256

import httpx


def sha256sum(path: str) -> str:
    """
    Computes sha256 hash sum of a file.

    Args:
        path: path of file

    Returns:
        hex digest of sha256
    """
    hash = sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(4096), b""):
            hash.update(buf)
    return str(hash.hexdigest())


def sign(key, msg):
    """
    Modified from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    """
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, serviceName):
    """
    Modified from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    """
    kDate = sign(("TC3" + key).encode("utf-8"), dateStamp)
    kService = sign(kDate, serviceName)
    kSigning = sign(kService, "tc3_request")
    return kSigning


class QCloudHttpxAuth(httpx.Auth):
    """
    Auth class that allows us to connect to QCloud services
    """

    requires_request_body = True

    def __init__(
        self,
        qcloud_secret_id,
        qcloud_secret_key,
        qcloud_host,
        qcloud_region,
        qcloud_service,
        qcloud_action,
        qcloud_apiversion,
    ):
        """
        Example usage for talking to an QCloud CVM API:

        QCloudHttpxAuth(qcloud_access_key='YOURKEY',
                           qcloud_secret_access_key='YOURSECRET',
                           qcloud_host='cvm.tencentcloudapi.com',
                           qcloud_region='ap-shanghai',
                           qcloud_service='cvm')

        """
        self.qcloud_secret_id = qcloud_secret_id
        self.qcloud_secret_key = qcloud_secret_key
        self.qcloud_host = qcloud_host
        self.qcloud_region = qcloud_region
        self.qcloud_service = qcloud_service
        self.qcloud_action = qcloud_action
        self.qcloud_apiversion = qcloud_apiversion

    def auth_flow(self, r: httpx.Request) -> typing.Generator[httpx.Request, httpx.Response, None]:
        """
        Adds the authorization headers required by QCloud Signature v3.
        """
        qcloud_headers = self.get_qcloud_request_headers_handler(r)
        r.headers.update(qcloud_headers)
        yield r

    def get_qcloud_request_headers_handler(self, r):
        """
        Override get_qcloud_request_headers_handler() if you have a
        subclass that needs to call get_qcloud_request_headers() with
        an arbitrary set of QCloud credentials. The default implementation
        calls get_qcloud_request_headers() with self.qcloud_access_key,
        and self.qcloud_secret_access_key
        """
        return self.get_qcloud_request_headers(
            r=r, qcloud_secret_id=self.qcloud_secret_id, qcloud_secret_key=self.qcloud_secret_key
        )

    def get_qcloud_request_headers(self, r: httpx.Request, qcloud_secret_id, qcloud_secret_key):
        """
        Returns a dictionary containing the necessary headers for Amazon's
        signature version 4 signing process. An example return value might
        look like

            {
                'Authorization': '...',
                '...',
            }
        """
        # Create a date for headers and the credential string
        t = datetime.datetime.now()
        amzdate = str(int(t.timestamp()))
        datestamp = t.utcfromtimestamp(t.timestamp()).strftime("%Y-%m-%d")  # Date w/o time for credential_scope

        canonical_uri = QCloudHttpxAuth.get_canonical_path(r)

        canonical_querystring = QCloudHttpxAuth.get_canonical_querystring(r)

        if r.headers.get("content-type") is None:
            if not r.method == "GET":
                raise ValueError("content-type must be set for non GET methods")
            r.headers["content-type"] = "application/x-www-form-urlencoded"

        # Create the canonical headers and signed headers. Header names
        # and value must be trimmed and lowercase, and sorted in ASCII order.
        # Note that there is a trailing \n.
        canonical_headers = (
            "content-type:" + r.headers.get("content-type", "") + "\n" + "host:" + self.qcloud_host + "\n"
        )

        # Create the list of signed headers. This lists the headers
        # in the canonical_headers list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; canonical_headers and
        # signed_headers lists those that you want to be included in the
        # hash of the request. "Host" and "x-amz-date" are always required.
        signed_headers = "content-type;host"

        # Create payload hash (hash of the request body content). For GET
        # requests, the payload is an empty string ('').

        payload_hash = hashlib.sha256(r.read()).hexdigest()

        # Combine elements to create create canonical request
        canonical_request = (
            r.method
            + "\n"
            + canonical_uri
            + "\n"
            + canonical_querystring
            + "\n"
            + canonical_headers
            + "\n"
            + signed_headers
            + "\n"
            + payload_hash
        )

        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        algorithm = "TC3-HMAC-SHA256"
        credential_scope = datestamp + "/" + self.qcloud_service + "/" + "tc3_request"
        string_to_sign = (
            algorithm
            + "\n"
            + amzdate
            + "\n"
            + credential_scope
            + "\n"
            + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
        )

        # Create the signing key using the function defined above.
        signing_key = getSignatureKey(qcloud_secret_key, datestamp, self.qcloud_service)

        # Sign the string_to_sign using the signing_key
        string_to_sign_utf8 = string_to_sign.encode("utf-8")

        signature = hmac.new(signing_key, string_to_sign_utf8, hashlib.sha256).hexdigest()

        # The signing information can be either in a query string value or in
        # a header named Authorization. This code shows how to use a header.
        # Create authorization header and add to request headers
        authorization_header = (
            algorithm
            + " "
            + "Credential="
            + qcloud_secret_id
            + "/"
            + credential_scope
            + ", "
            + "SignedHeaders="
            + signed_headers
            + ", "
            + "Signature="
            + signature
        )

        headers = {
            "Authorization": authorization_header,
            "x-tc-timestamp": amzdate,
            "x-tc-action": self.qcloud_action,
            "x-tc-region": self.qcloud_region,
            "x-tc-version": self.qcloud_apiversion,
        }
        return headers

    @classmethod
    def get_canonical_path(cls, r: httpx.Request):
        """
        Create canonical path. According to QCloud, this should always be "/"
        """
        return "/"

    @classmethod
    def get_canonical_querystring(cls, r: httpx.Request):
        """
        Create the canonical query string. According to QCloud, by the
        end of this function our query string values must
        be URL-encoded (space=%20) and the parameters must be sorted
        by name.

        This method assumes that the query params in `r` are *already*
        url encoded.  If they are not url encoded by the time they make
        it to this function, QCloud may complain that the signature for your
        request is incorrect.

        It appears elasticsearc-py url encodes query paramaters on its own:
            https://github.com/elastic/elasticsearch-py/blob/5dfd6985e5d32ea353d2b37d01c2521b2089ac2b/elasticsearch/connection/http_requests.py#L64

        If you are using a different client than elasticsearch-py, it
        will be your responsibility to urleconde your query params before
        this method is called.
        """
        canonical_querystring = b""

        querystring_sorted = b"&".join(sorted(r.url.query.split(b"&")))

        for query_param in querystring_sorted.split(b"&"):
            key_val_split = query_param.split(b"=", 1)

            key = key_val_split[0]
            if len(key_val_split) > 1:
                val = key_val_split[1]
            else:
                val = b""

            if key:
                if canonical_querystring:
                    canonical_querystring += b"&"
                canonical_querystring += b"=".join([key, val])

        # FIXME: use bytes instead of decode. httpx's request is better.
        return canonical_querystring.decode()
