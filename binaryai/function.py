from .graphql.function import q_create_function, q_query_function, q_create_function_set, q_saveto_function_set_members
from .graphql.function import q_query_function_set, q_query_created_function_set, q_search_func_similarity
from .graphql.function import q_search_func_similarity_by_feature
from .graphql.function import q_clear_retrieve_list, q_insert_retrieve_list, q_retrieve_list_count
from .client import Client
from .utils import BinaryAIException
import time


def upload_function(
        client,
        name,
        feature,
        source_code=None,
        source_file=None,
        source_line=None,
        binary_file=None,
        binary_sha256=None,
        fileoffset=None,
        _bytes=None,
        platform=None,
        throw_duplicate_error=False,
        pseudo_code=None,
        package_name=None
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
        binary_file(string): Name of the binary file which contains this function
        binary_sha256(string): Hash (sha256) of the binary file
        fileoffset(int): File offset of the function
        _bytes(string): Binary data of the function
        platform(string): Platform of the binary file, for example, metapc64, or x86_64, or mipsel
        throw_duplicate_error(bool): If a duplicate error should be raised when two name equals
        pseudo_code(string): Pseudo code of the function
        package_name(string): Package name containing this function

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
        'binarySha256': binary_sha256,
        'fileoffset': fileoffset,
        'bytes': _bytes,
        'platform': platform,
        'pseudoCode': pseudo_code,
        'packageName': package_name
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


def create_function_set(client, name, description="", function_ids=None, throw_duplicate_error=True):
    '''
    Create a new function set and add functions if needed

    Args:
        client(binaryai.client.Client): Client instance
        name(string): Name of the new functionset
        description(string): Description of the new functionset.
                             Can be empty string
        function_ids(list): Functions to be inserted into the new function set.
                            Can be None if there are no functions to be added into the set.

    Returns:
        * **id** (string) -- id of the function set
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        'name': name,
        "description": description,
    }
    r = client.execute(q_create_function_set, var, throw_duplicate_error=throw_duplicate_error)
    set_id = r['createFunctionSet']['functionSet']['id']
    if not len(set_id) > 0:
        raise BinaryAIException("SDK_ERROR", "create functionset failed")
    if function_ids is not None:
        var = {
            'setID': set_id,
            "functionIds": function_ids,
        }
        r = client.execute(q_saveto_function_set_members, var)
        new_set_id = r['saveToFunctionSetMembers']['functionSet']['id']
        if not len(set_id) == len(new_set_id):
            raise BinaryAIException("SDK_ERROR", "insert functionset failed")
    return set_id


def saveto_function_set_members(client, setid, function_ids):
    '''
    Save a function to the function set

    Args:
        client(binaryai.client.Client): Client instance
        setid(string): ID of the target
        function_ids(list): Functions to be inserted into the new function set.
                            Can be None if there are no functions to be added into the set.

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
    r = client.execute(q_saveto_function_set_members, var)
    new_set_id = r['saveToFunctionSetMembers']['functionSet']['id']
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


def query_created_function_set(client):
    '''
    Get all function sets created by current user

    Returns:
        * **functionSetIDs** (list) -- functionSet's id
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {}
    result = client.execute(q_query_created_function_set, var)
    return [node["id"] for node in result["viewer"]["createdFunctionSets"]["nodes"]]


def search_sim_funcs(client, function_id=None, feature=None, topk=1):
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
        return r['retrieveList']['searchByID']
    elif feature is not None:
        var = {
            'feature': feature,
            'topk': topk
        }
        r = client.execute(q_search_func_similarity_by_feature, var)
        return r['retrieveList']['searchByRepresentation']
    raise BinaryAIException("SDK_ERROR", "all arguments are None")


def clear_retrieve_list(client):
    '''
    Clear all things in your retrieve list

    Returns:
        None
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {}
    client.execute(q_clear_retrieve_list, var)
    return None


def insert_retrieve_list(client, function_ids=None, functionset_ids=None):
    '''
    Insert functions into your retrieve list

    Args:
        client(binaryai.client.Client): Client instance
        function_ids(list): Functions to be inserted into the index list.
                            Can be None if there are no functions to be added into the set.
        functionset_ids(list): Functionsets to be inserted into the index list.
                            Can be None if there are no functions to be added into the set.

    Returns:
        None
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        "functionid": function_ids,
        "functionsetid": functionset_ids
    }
    # do a back-off based retry
    # maybe we not synced
    backoff_time = [0, 0.05, 0.1, 0.1, 0.25, 0.5]
    exc = None
    for i in backoff_time:
        time.sleep(i)
        try:
            client.execute(q_insert_retrieve_list, var)
        except Exception as e:
            exc = e
        else:
            return None
    if exc is not None:
        raise exc
    return None


def query_retrieve_list_count(client):
    '''
    query function count in the retrieve list

    Args:
        client(binaryai.client.Client): Client instance

    Returns:
        * **total_count** (int) -- the total count of items in the retrieve list.
    '''
    if not isinstance(client, Client):
        raise BinaryAIException("SDK_ERROR", "Invalid client argument", None, None)
    var = {
        "offset": 0,
        "limit": 20,
        "isFunction": True
    }
    r = client.execute(q_retrieve_list_count, var)
    return r['retrieveList']['functions']['totalCount']
