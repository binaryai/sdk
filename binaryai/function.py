from .graphql.function import q_create_function, q_query_function, q_create_function_set, q_insert_function_set_members
from .graphql.function import q_query_function_set, q_query_created_function_set, q_search_func_similarity, q_search_func_similarity_by_feature, q_clear_index_list, q_insert_index_list
from .client import Client
from .error import BinaryAIException


def upload_function(
        client,
        name,
        feature,
        *,
        source_code=None,
        source_file=None,
        source_line=None,
        binary_file=None,
        platform=None,
        throw_duplicate_error=False,
) -> str:
    '''
    upload function to BinaryAI server

    Args:
        client(binaryai.client.Client): Client instance
        name(string): name of the function
        feature(string): Feature of the function. Genertaed by feature extraction library. Encoding in base64.
        source_code(string): Source code of the function
        source_file(string): Source file of the function
        source_line(int): line number of the function
        binary_file(string): Name of the binary file which contains this function
        platform(string): Platform of the binary file, for example, metapc64, or x86_64, or mipsel
        throw_duplicate_error(bool): If a duplicate error should be raised when two name equals

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
        'binaryFileName': binary_file,
        'platform': platform
    }
    r = client.execute(q_create_function, var, throw_duplicate_error=throw_duplicate_error)
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


def create_function_set(client, name: str, description: str="", *, function_ids: list=None) -> str:
    '''
    Create a new function set and add functions if needed

    Args:
        client(binaryai.client.Client): Client instance
        name(string): Name of the new functionset
        description(string): Description of the new functionset.
                             Can be empty string
        function_ids(list): Functions to be inserted into the new function set.
                            Can be null so no functions will be added into the set.

    Returns:
        * **id** (string) -- id of the function set
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        'name': name,
        "description": description,
    }
    r = client.execute(q_create_function_set, var)
    set_id = r['createFunctionSet']['functionSet']['id']
    if not len(set_id) > 0:
        raise BinaryAIException("SDK_ERROR", "create functionset failed")
    if function_ids is not None:
        var = {
            'setID': set_id,
            "functionIds": function_ids,
        }
        r = client.execute(q_insert_function_set_members, var)
        new_set_id = r['insertFunctionSetMembers']['functionSet']['id']
        if not len(set_id) == len(new_set_id):
            raise BinaryAIException("SDK_ERROR", "insert functionset failed")
    return set_id


def insert_function_set_member(client, setid: str, function_ids: list) -> str:
    '''
    Insert functions into certain functionset

    Args:
        client(binaryai.client.Client): Client instance
        setid(string): ID of the target
        function_ids(list): Functions to be inserted into the new function set.
                            Can be null so no functions will be added into the set.

    Returns:
        * **id** (string) -- id of the function set
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    assert(isinstance(function_ids, list))
    assert(len(setid) > 0)
    if len(function_ids) == 0:
        return setid
    var = {
        'setID': setid,
        "functionIds": function_ids,
    }
    r = client.execute(q_insert_function_set_members, var)
    new_set_id = r['insertFunctionSetMembers']['functionSet']['id']
    if not setid == new_set_id:
        raise BinaryAIException("SDK_ERROR", "insert functionset failed")
    return new_set_id

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
    if 'functionSet' not in r or r['functionSet'] is None:
        raise BinaryAIException("SDK_ERROR", "Invalid function set id")
    if funcset_id != r['functionSet']['id']:
        raise BinaryAIException("SDK_ERROR", "Response function set id not equal to the funcset_id", r, None)
    return r['functionSet']

def query_created_function_set(client) -> list:
    '''
    Get all function sets created by current user

    Returns:
        * **functionSetIDs** (list) -- functionSet's id
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {}
    l = client.execute(q_clear_index_list, var)
    return [node["id"] for node in l["viewer"]["createdFunctionSets"]["nodes"]]

def search_sim_funcs(client, function_id=None, *, feature=None, topk=1):
    '''
    search top similar functions of the function in your retrieve list

    Args:
        client(binaryai.client.Client): Client instance
        function_id(string): id of the function
        topk(int): return first topk results, default value is 1.

    Returns:
        * **similarity** (list): list of the top similarity functions
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    if function_id is not None:
        var = {
            'funcId': function_id,
            'topk': topk
        }
        r = client.execute(q_search_func_similarity, var)
        return r['indexList']['searchByID']
    elif feature is not None:
        var = {
            'feature': feature,
            'topk': topk
        }
        r = client.execute(q_search_func_similarity_by_feature, var)
        return r['indexList']['searchByRepresentation']
    raise BinaryAIException("SDK_ERROR", "all arguments are None")

def clear_index_list(client):
    '''
    Clear all things in your index list

    Returns:
        None
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {}
    client.execute(q_clear_index_list, var)
    return None

def insert_index_list(client, *, function_ids: list = None, functionset_ids: list = None):
    '''
    Insert functions into your retrive list

    Args:
        client(binaryai.client.Client): Client instance
        function_ids(list): Functions to be inserted into the index list.
                            Can be null so no functions will be added into the list.
        functionset_ids(list): Functionsets to be inserted into the index list.
                            Can be null so no sets will be added into the list.

    Returns:
        None
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        "functionid": function_ids,
        "functionsetid": functionset_ids
    }
    client.execute(q_insert_index_list, var)
    return None