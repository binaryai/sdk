import requests
import json


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
            raise RuntimeError("Request failed with exception: {}".format(e))

        try:
            jdata = json.loads(response.content)
        except Exception:
            raise RuntimeError("Invalid response: {}".format(response.content))

        if "errors" in jdata.keys():
            raise RuntimeError("{}".format(jdata["errors"][0]["message"]))

        if "data" not in jdata.keys():
            raise RuntimeError("Invalid response from server: {}".format(response.content))

        return jdata["data"]
