import random
import string
import time
import binaryai as bai


def random_name(N):
    return ''.join([random.choice(string.ascii_uppercase + string.digits) for _ in range(N)])


def test_search_sim_func_1(client, data_1):
    func_feat = data_1.sample(1).iloc[0].sample(1).iloc[0]
    func_name = random_name(8)
    func_id = bai.function.upload_function(client, func_name, func_feat, source_code=func_feat)
    funcset_name = random_name(32)
    funcset_id = bai.function.create_function_set(client, funcset_name)
    bai.function.saveto_function_set_members(client, funcset_id, [func_id])
    # Sleep 1 sec to ensure all embeddings have been transfered
    time.sleep(1)
    bai.function.clear_retrieve_list(client)
    bai.function.insert_retrieve_list(client, functionset_ids=[funcset_id])
    # Sleep 1 sec to ensure index list flushed
    time.sleep(1)
    sim = bai.function.search_sim_funcs(client, func_id, topk=1)
    assert len(sim) == 1
    assert sim[0]['function']['id'] == func_id
    assert sim[0]['score'] >= 0.9999


def test_search_sim_func_2(client, data_1):
    name = random_name(32)
    corpus_set = bai.function.create_function_set(client, name)

    func_names = []
    df = data_1.sample(2, axis=1)
    for _, row in df.iterrows():
        func_feat = row.iloc[0]
        func_name = random_name(8)
        func_names.append(func_name)
        func_id = bai.function.upload_function(client, func_name, func_feat, source_code=func_feat)
        bai.function.saveto_function_set_members(client, corpus_set, [func_id])

    # Sleep 1 sec to ensure all embeddings have been transfered
    time.sleep(1)

    bai.function.clear_retrieve_list(client)
    bai.function.insert_retrieve_list(client, functionset_ids=[corpus_set])

    # Sleep 1 sec to ensure index list flushed
    time.sleep(1)

    count = 0
    for _, row in df.iterrows():
        func_feat = row.iloc[1]
        func_name = func_names[count]
        sim = bai.function.search_sim_funcs(client, feature=func_feat, topk=3)
        top3_names = [s['function']['name'] for s in sim]
        assert func_name in top3_names
        count += 1
