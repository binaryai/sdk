import json
import binaryai as bai
import random
import string

random_name = lambda N: ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

def test_search_sim_func_1(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    name = random_name(32)
    funcset_id = bai.function.create_function_set(client, name)
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(
        client, func_name, func_feat)
    bai.function.insert_function_set_member(client, funcset_id, [func_id])
    bai.function.clear_index_list(client)
    bai.function.insert_index_list(client, functionset_ids=[funcset_id])
    sim = bai.function.search_sim_funcs(client, func_id, topk=1)
    assert len(sim) == 1
    assert sim[0]['function']['id'] == func_id
    assert sim[0]['score'] >= 0.9999


def test_search_sim_func_2(client, data_1):
    bai.function.clear_index_list(client)
    df1 = data_1.sample(1, axis=1)
    df2 = df1
    while df2.columns[0] == df1.columns[0]:
        df2 = data_1.sample(1, axis=1)

    name = random_name(32)
    corpus_set = bai.function.create_function_set(client, name)
    for _, row in df1.iterrows():
        func_feat = row.iloc[0]
        func = json.loads(func_feat)
        func_id = bai.function.upload_function(
            client, func['graph']['name'], func_feat)
        bai.function.insert_function_set_member(client, corpus_set, [func_id])

    for _, row in df2.iterrows():
        func_feat = row.iloc[0]
        func = json.loads(func_feat)
        name = func['graph']['name']
        func_id = bai.function.upload_function(
            client, func['graph']['name'], func_feat)
        bai.function.insert_index_list(client, functionset_ids=[corpus_set])
        sim = bai.function.search_sim_funcs(
            client, func_id, topk=3)
        top3_names = [s['function']['name'] for s in sim]
        assert name in top3_names
