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
        self.session = self._token_verify()
        self.GMT_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
        self.timeout = timeout

    def _token_verify(self):
        session = requests.Session()
        try:
            response = session.get(self.url, headers=self.headers)
        except Exception as e:
            raise BinaryAIException("SDK_ERROR", "Request failed with exception: {}".format(e))
        else:
            if response.status_code == 401:
                raise BinaryAIException("SDK_ERROR", "UNAUTHENTICATED: Invalid token")
            elif response.status_code == 200:
                return session
            else:
                raise BinaryAIException("SDK_ERROR", "Invalid response: [{}] {}".format(
                    response.status_code, response.content))
        finally:
            return

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
            raise BinaryAIException("SDK_ERROR", "Request failed with exception: {}".format(e))

        try:
            jdata = json.loads(response.content)
        except Exception:
            raise BinaryAIException("SDK_ERROR", "Invalid response: {}".format(response.content))

        if "errors" in jdata.keys():
            errors = jdata["errors"][0]
            raise BinaryAIException(errors['extensions']['code'], errors['message'], jdata['data'], jdata)

        if "data" not in jdata.keys():
            raise BinaryAIException("SDK_ERROR", "Invalid response: {}".format(response.content))

        return jdata["data"]
