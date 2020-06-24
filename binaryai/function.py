from .graphql.function import q_create_function, q_query_function, q_create_function_set
from .graphql.function import q_query_function_set, q_search_func_similarity
from .client import Client
from .error import BinaryAIException


def upload_function(
        client,
        name,
        feature,
        source_code=None,
        source_file=None,
        source_line=None,
        language=None,
        funcset_id=None
):
    '''
    upload function to BinaryAI server

    Args:
        client(binaryai.client.Client): Client instance
        name(string): name of the function
        feature(string): Feature of the function. Genertaed by feature extraction library. Encoding in base64.
        source_code(string): Source code of the function
        source_file(string): Source file of the function
        source_line(int): line number of the function
        language(string): Programming language of the function
        funcset_id(string): If functionSetID specified, it would be added into that set when adding function;
                            if not, it would not be added into any set

    Returns:
        * **id** (string) -- id of this function
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        'name': name,
        'feature': feature,
        'sourceCode': source_code,
        'sourceFile': source_file,
        'sourceLine': source_line,
        'language': language,
        'functionSetId': funcset_id
    }
    r = client.execute(q_create_function, var)
    return r['createFunction']['function']['id']


def query_function(client, function_id):
    '''
    get function information by id

    Args:
        client(binaryai.client.Client): Client instance
        function_id(string): ID of the function

    Returns:
        * **function** (dict) -- Function's information
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        'funcId': function_id
    }
    r = client.execute(q_query_function, var)
    if r['function'] and function_id != r['function']['id']:
        raise BinaryAIException("SDK_ERROR", "Response function id not equal to the function_id", r, None)
    return r['function']


def create_function_set(client, function_ids=None):
    '''
    Create a new function set and add functions if needed

    Args:
        client(binaryai.client.Client): Client instance
        function_ids(list): Functions to be inserted into the new function set.
                            Can be null so no functions will be added into the set.

    Returns:
        * **id** (string) -- id of the function set
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        'functionIds': function_ids
    }
    r = client.execute(q_create_function_set, var)
    return r['createFunctionSet']['functionSet']['id']


def query_function_set(client, funcset_id):
    '''
    get function set information by id

    Args:
        client(binaryai.client.Client): Client instance
        funcset_id(string): id of the function set

    Returns:
        * **functionSet** (dict) -- functionSet's information
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        'funcSetId': funcset_id
    }
    r = client.execute(q_query_function_set, var)
    if funcset_id != r['functionSet']['id']:
        raise BinaryAIException("SDK_ERROR", "Response function set id not equal to the funcset_id", r, None)
    return r['functionSet']


def search_sim_funcs(client, function_id, funcset_ids=None, topk=1):
    '''
    search top similar functions of the function

    Args:
        client(binaryai.client.Client): Client instance
        function_id(string): id of the function
        funcset_ids(list): ids of the function set to be compared, None means BinaryAI official sets.
        topk(int): return first topk results, default value is 1.

    Returns:
        * **similarity** (list): list of the top similarity functions
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        'funcId': function_id,
        'setId': funcset_ids,
        'topk': topk
    }
    r = client.execute(q_search_func_similarity, var)
    return r['function']['similarity']
