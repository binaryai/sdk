import os
import json
import pandas as pd
import binaryai as bai
from binaryai.error import BinaryAIException


def test_official_funset_1(client, testdata):
    func_feat = testdata.sample(1).iloc[0].sample(1).iloc[0]
    func_id = bai.function.upload_function(client, "foo", func_feat)

    sim = bai.function.search_sim_funcs(
        client,
        func_id, topk=5
    )
    assert len(sim) == 5

    try:
        sim = bai.function.search_sim_funcs(client, func_id, topk=0)
    except BinaryAIException as e:
        assert str(e) == "INVALID_ARGUMENT: Argument topK can not be zero or negative"
    else:
        raise RuntimeError("Backend didn't catch \"INVALID_ARGUMENT: Argument topK can not be zero or negative\"")

    try:
        sim = bai.function.search_sim_funcs(
            client,
            func_id, topk=1234567890
        )
    except BinaryAIException as e:
        assert e.code == "INVALID_ARGUMENT_TOPK_EXCEED_CAPACITY"
        sim = e.data
        assert sim is not None
    else:
        raise RuntimeError("Backend didn't catch \"INVALID_ARGUMENT_TOPK_EXCEED_CAPACITY\"")


def test_official_funset_2(client, testdata):
    df = pd.read_pickle("{}/../testdata/test_official.pkl".format(os.path.dirname(__file__)))
    assert len(df) == 2
    pos, neg = df.iloc[0]['gcc-x64-O0'], df.iloc[1]['gcc-x64-O0']
    pos_name = json.loads(pos)['graph']['name']

    func_id = bai.function.upload_function(client, "pos", pos)
    sim = bai.function.search_sim_funcs(
        client,
        func_id, topk=1
    )
    assert sim[0]['score'] > 0.99
    assert sim[0]['function']['name'] == pos_name

    func_id = bai.function.upload_function(client, "neg", neg)
    sim = bai.function.search_sim_funcs(
        client,
        func_id, topk=1
    )
    assert sim[0]['score'] < 0.8
