import requests
import json
from .utils import BinaryAIException


class Client(object):
    '''
    BinaryAI api client

    Attributes:
        token(string): token used for query
        url(string): BinaryAI api endpoint url
        timeout(int): seconds of timeout, default is 1000
    '''

    def __init__(
        self,
        token,
        url,
        timeout=1000,
    ):
        self.token = token
        self.url = url
        self.session = None
        self._verify(self.token, self.url)
        self.GMT_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
        self.timeout = timeout

    def _gen_gql_data(self, query, var):
        data = {
            "operationName": None,
            "variables": var,
            "query": query
        }
        return data

    def _verify(self, token, url):
        try:
            response = requests.get(url, headers={"Token": token})
        except Exception as e:
            raise BinaryAIException("SDK_ERROR", "Request failed with exception: {}".format(e))
        else:
            if response.status_code == 401:
                raise BinaryAIException("SDK_ERROR", "UNAUTHENTICATED: Invalid token")
            elif response.status_code == 200:
                return
            else:
                raise BinaryAIException("SDK_ERROR", "Invalid response: [{}] {}".format(
                    response.status_code, response.content))

    def execute(self, query, var, throw_duplicate_error=False):
        '''
        Send request to API server and get response

        Args:
            query(string): graphql query
            var(dict): variables to send

        Returns:
            dict: response data of this request
        '''
        if not self.session:
            self.session = requests.Session()
        data = self._gen_gql_data(query, var)
        headers = {
            "Content-Type": "application/json",
            "Token": self.token
        }
        response = None
        try:
            response = self.session.post(self.url, data=json.dumps(
                data), headers=headers, timeout=self.timeout)
        except Exception as e:
            raise BinaryAIException("SDK_ERROR", "Request failed with exception: {}".format(e))

        try:
            jdata = json.loads(response.content)
        except Exception:
            raise BinaryAIException("SDK_ERROR", "Invalid response: {}".format(response.content))

        if "errors" in jdata.keys():
            errors = jdata["errors"][0]
            code = errors['extensions']['code']
            if code == "INVALID_ARGUMENT_DUPLICATE_ARGUMENT" and not throw_duplicate_error:
                pass
            else:
                data = jdata['data'] if 'data' in jdata.keys() else None
                raise BinaryAIException(code, errors['message'], data, jdata)

        if "data" not in jdata.keys():
            raise BinaryAIException("SDK_ERROR", "Invalid response: {}".format(response.content))

        return jdata["data"]
