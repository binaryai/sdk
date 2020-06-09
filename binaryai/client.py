import requests
import json
from .error import BinaryAIException


class Client(object):
    '''
    BinaryAI api client

    Attributes:
        token(string): token used for query
        url(string): BinaryAI api endpoint url, default is https://api.binaryai.tencent.com/v1/endpoint
        timeout(int): seconds of timeout, default is 1000
    '''

    def __init__(
        self,
        token,
        url="https://api.binaryai.tencent.com/v1/endpoint",
        timeout=1000,
    ):
        self.url = url
        self.headers = {
            "Content-Type": "application/json",
            "token": token
        }
        self.session = None
        self.GMT_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
        self.timeout = timeout

    def _gen_gql_data(self, query, var):
        data = {
            "operationName": None,
            "variables": var,
            "query": query
        }
        return data

    def execute(self, query, var):
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
        response = None
        try:
            response = self.session.post(self.url, data=json.dumps(
                data), headers=self.headers, timeout=self.timeout)
        except Exception as e:
            raise BinaryAIException("SDK_ERROR", "Request failed with exception: {}".format(e), None, None)

        try:
            jdata = json.loads(response.content)
        except Exception:
            raise BinaryAIException("SDK_ERROR", "Invalid response: {}".format(response.content), None, None)

        if "errors" in jdata.keys():
            errors = jdata["errors"][0]
            raise BinaryAIException(errors['extensions']['code'], errors['message'], jdata['data'], jdata)

        if "data" not in jdata.keys():
            raise BinaryAIException("SDK_ERROR", "Invalid response: {}".format(response.content), None, None)

        return jdata["data"]
