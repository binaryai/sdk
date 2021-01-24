import random
import string
import binaryai as bai


def random_name(N):
    return ''.join([random.choice(string.ascii_uppercase + string.digits) for _ in range(N)])


def test_create_funcset_1(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    func_name = random_name(8)
    func_id = bai.function.upload_function(client, func_name, func_feat, source_code=func_feat)
    assert func_id is not None
    name = random_name(32)
    funcset_id = bai.function.create_function_set(client, name, function_ids=[func_id])
    assert funcset_id is not None
    fset = bai.function.query_function_set(client, funcset_id)
    fset_id, funcs = fset['id'], fset['functions']['nodes']
    assert fset_id == funcset_id
    assert len(funcs) == 1
    assert func_id == funcs[0]['id']


def test_create_funcset_2(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    name = random_name(32)
    funcset_id = bai.function.create_function_set(client, name)
    assert funcset_id is not None
    func_name = random_name(8)
    func_id = bai.function.upload_function(
        client, func_name, func_feat, source_code=func_feat)
    bai.function.saveto_function_set_members(client, funcset_id, [func_id])
    assert func_id is not None
    fset = bai.function.query_function_set(client, funcset_id)
    fset_id, funcs = fset['id'], fset['functions']['nodes']
    assert fset_id == funcset_id
    assert len(funcs) == 1
    assert func_id == funcs[0]['id']


def test_create_funcset_3(client, data_1):
    func_feats = data_1.sample(1).iloc[0].values
    func_ids = []
    for func_feat in func_feats:
        func_name = random_name(8)
        func_id = bai.function.upload_function(client, func_name, func_feat, source_code=func_feat)
        func_ids.append(func_id)
    name = random_name(32)
    funcset_id = bai.function.create_function_set(client, name, function_ids=func_ids)
    fset = bai.function.query_function_set(client, funcset_id)
    funcs = fset['functions']['nodes']
    assert len(funcs) == len(func_ids)
    assert set([func['id'] for func in funcs]) == set(func_ids)


def test_create_funcset_4(client):
    name = random_name(32)
    funcset_id_A = bai.function.create_function_set(client, name)
    funcset_id_B = bai.function.create_function_set(client, name, throw_duplicate_error=False)
    assert funcset_id_A == funcset_id_B


def test_query_empty_funcset(client):
    name = random_name(32)
    funcset_id = bai.function.create_function_set(client, name)
    fset = bai.function.query_function_set(client, funcset_id)
    funcs = fset['functions']['nodes']
    assert not funcs
