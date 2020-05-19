import json
import binaryai as bai


def test_upload_and_query(client, testdata):
    func_feat = testdata.sample(1).iloc[0].sample(1).iloc[0]
    func = json.loads(func_feat)
    func_name = func['graph']['name']
    func_id = bai.function.upload_function(client, func_name, func_feat)
    assert func_id is not None
    res = bai.function.query_function(client, func_id)
    assert func_id == res['id']
    assert func_name == res['name']
