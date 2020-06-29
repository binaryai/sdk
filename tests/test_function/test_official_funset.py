import json
import binaryai as bai


def test_official_funset_1(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    func_id = bai.function.upload_function(client, "foo", func_feat)

    sim = bai.function.search_sim_funcs(
        client,
        func_id, topk=5
    )
    assert len(sim) == 5


def test_official_funset_2(client, data_2):
    assert len(data_2) == 2
    pos, neg = data_2.iloc[0]['feat'], data_2.iloc[1]['feat']
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
    assert sim[0]['score'] < 0.9
