import json
import binaryai as bai
from binaryai import BinaryAIException


def test_upload_and_query(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(client, func_name, func_feat)
    assert func_id is not None
    res = bai.function.query_function(client, func_id)
    assert func_id == res['id']
    assert func_name == res['name']


def test_remove_duplicate_funcid(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id1 = bai.function.upload_function(client, func_name, func_feat)
    func_id2 = bai.function.upload_function(client, func_name, func_feat)
    assert func_id1 == func_id2


def test_query_with_topk(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    func_id = bai.function.upload_function(client, "foo", func_feat)

    sim = bai.function.search_sim_funcs(client, func_id, topk=0)
    assert sim is None

    try:
        sim = bai.function.search_sim_funcs(client, func_id, topk=-1)
    except BinaryAIException as e:
        assert e.code == "INVALID_ARGUMENT"
    else:
        assert False, "Backend didn't throw Exception: INVALID_ARGUMENT"

    try:
        funcset_id = bai.function.create_function_set(client)
        sim = bai.function.search_sim_funcs(client, func_id, topk=1, funcset_ids=[funcset_id])
    except BinaryAIException as e:
        assert e.code == "INVALID_ARGUMENT_TOPK_EXCEED_CAPACITY"
    else:
        assert False, "Backend didn't throw Exception: INVALID_ARGUMENT_TOPK_EXCEED_CAPACITY"

    try:
        sim = bai.function.search_sim_funcs(client, func_id, topk=1234567890)
    except BinaryAIException as e:
        assert e.code == "INVALID_ARGUMENT_TOPK_EXCEED_CAPACITY"
        sim = e.data
        assert sim is not None
    else:
        assert False, "Backend didn't throw Exception: INVALID_ARGUMENT_TOPK_EXCEED_CAPACITY"
