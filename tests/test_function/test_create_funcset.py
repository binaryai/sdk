import json
import binaryai as bai


def test_create_funcset_1(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(client, func_name, func_feat)
    assert func_id is not None
    funcset_id = bai.function.create_function_set(client, [func_id])
    assert funcset_id is not None
    fset = bai.function.query_function_set(client, funcset_id)
    fset_id, funcs = fset['id'], fset['functions']
    assert fset_id == funcset_id
    assert len(funcs) == 1
    assert func_id == funcs[0]['id']


def test_create_funcset_2(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    funcset_id = bai.function.create_function_set(client)
    assert funcset_id is not None
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(
        client, func_name, func_feat, funcset_id=funcset_id)
    assert func_id is not None
    fset = bai.function.query_function_set(client, funcset_id)
    fset_id, funcs = fset['id'], fset['functions']
    assert fset_id == funcset_id
    assert len(funcs) == 1
    assert func_id == funcs[0]['id']


def test_create_funcset_3(client, data_1):
    func_feats = data_1.sample(1).iloc[0].values
    func_ids = []
    for func_feat in func_feats:
        func = json.loads(func_feat)
        func_name = func['graph']['name']
        func_id = bai.function.upload_function(client, func_name, func_feat)
        func_ids.append(func_id)
    funcset_id = bai.function.create_function_set(client, func_ids)
    fset = bai.function.query_function_set(client, funcset_id)
    funcs = fset['functions']
    assert len(funcs) == len(func_ids)
    assert set([func['id'] for func in funcs]) == set(func_ids)


def test_query_empty_funcset(client):
    funcset_id = bai.function.create_function_set(client)
    fset = bai.function.query_function_set(client, funcset_id)
    funcs = fset['functions']
    assert funcs is None
