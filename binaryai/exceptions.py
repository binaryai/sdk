from typing import Dict, List, Optional


class BinaryAIGQLErrorDetail(object):
    """
    A single GraphQL response may contain multiple errors of different causes,
     each of which is parsed and stored a an GQLErrorDetail instance.
    The `error_source` field indicates the error source, which could be
    either client-sided or server-sided.

    Attributes:
        code: error code
        message: error message
        path: path of server-sided errors
        raw_data: raw error details in a dict
        error_source: [server|client] indicates the source of the error
    """

    error_codes = {
        "server": [
            "INTERNAL_SERVER_ERROR",
            "EXECUTE_NOT_FOUND",
            "FILE_NOT_FOUND",
            "DOWNSTREAM_SERVICE_ERROR",
        ],
        "client": ["INVALID_ARGUMENT_BAD_FORMAT", "GRAPHQL_VALIDATION_FAILED"],
    }

    def __init__(self, detail: Dict) -> None:
        """
        Initializes the instance with one member of the errors field
        in the original response.

        Args:
            detail: raw data structure of the given GQLError

        """
        self.code: str = detail["extensions"]["code"]
        self.message: str = detail["message"]
        self.path: Optional[Dict] = detail.get("path")
        self.raw_data: Dict = detail
        self.error_source: str = self.__get_error_source()

    def __get_error_source(self) -> str:
        for source in self.error_codes:
            if self.code in self.error_codes[source]:
                return source
        return "unknown"


class BinaryAIException(Exception):
    """
    An ambiguous error occurred when processing the request.
    """

    pass


class BinaryAIResponseError(BinaryAIException):
    """
    A response error typically means that the server responded
    unparsable data
    """

    pass


class BinaryAIGQLError(BinaryAIException):
    """
    There were error fields in the response of the GraphQL endpoint.
    The errors field holds a list of parsed error details.

    Attributes:
        trace_id: id of this GraphQL request
        errors: list of GQLErrorDetail instances
    """

    def __init__(self, trace_id: str, errors: List[BinaryAIGQLErrorDetail]) -> None:
        """
        Initializes the instance.
        """
        self.trace_id: str = trace_id
        self.errors: List[BinaryAIGQLErrorDetail] = []
        for e in errors:
            self.errors.append(BinaryAIGQLErrorDetail(e))

    def __str__(self) -> str:
        return "".join(["\n[{}] {}: {}".format(i + 1, e.code, e.message) for i, e in enumerate(self.errors)])

    def __repr__(self) -> str:
        return "[trace-ID={}]".format(self.trace_id) + "".join(
            [
                "\n[{}] ({} error) {}: {}".format(i + 1, e.error_source, e.code, e.message)
                for i, e in enumerate(self.errors)
            ]
        )


class FileNotExistError(Exception):
    """
    FileNotExistError means the sha256 just uploaded is not found.
    Normally this error does not occur. If it does, it means that there is
    a problem with the server
    """

    pass


class FileRequiredError(Exception):
    """
    FileRequiredError means BinaryAI requires the file, but you are not providing it.
    This error might occur if you are only providing hash to the BinaryAI. Consider provide the original file as well.
    """

    pass
