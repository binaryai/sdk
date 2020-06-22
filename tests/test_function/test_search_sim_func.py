import json
import binaryai as bai


def test_search_sim_func_1(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    funcset_id = bai.function.create_function_set(client)
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(
        client, func_name, func_feat, funcset_id=funcset_id)
    sim = bai.function.search_sim_funcs(client, func_id, [funcset_id], topk=1)
    assert len(sim) == 1
    assert sim[0]['function']['id'] == func_id
    assert sim[0]['score'] >= 0.9999


def test_search_sim_func_2(client, data_1):
    df1 = data_1.sample(1, axis=1)
    df2 = df1
    while df2.columns[0] == df1.columns[0]:
        df2 = data_1.sample(1, axis=1)

    corpus_set = bai.function.create_function_set(client)
    for _, row in df1.iterrows():
        func_feat = row.iloc[0]
        func = json.loads(func_feat)
        bai.function.upload_function(
            client, func['graph']['name'], func_feat, funcset_id=corpus_set)

    for _, row in df2.iterrows():
        func_feat = row.iloc[0]
        func = json.loads(func_feat)
        name = func['graph']['name']
        func_id = bai.function.upload_function(
            client, func['graph']['name'], func_feat)
        sim = bai.function.search_sim_funcs(
            client, func_id, [corpus_set], topk=3)
        top3_names = [s['function']['name'] for s in sim]
        assert name in top3_names
