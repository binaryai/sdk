# coding: utf-8
import idaapi
import idautils
import binaryai as bai


BINAYRAI_TOKEN = "PLEASE INPUT YOUR TOKEN HERE"
BINAYRAI_URL = "https://api.binaryai.tencent.com/v1/endpoint"


def upload_binary(client, funset_id, minsize=3):
    for func_ea in idautils.Functions():
        pfn = idaapi.get_func(func_ea)
        func_name = idaapi.get_func_name(func_ea)
        if idaapi.FlowChart(pfn).size < minsize:
            continue
        func_feat = bai.ida.get_func_feature(func_ea)
        if func_feat is None:
            continue
        bai.function.upload_function(client, func_name, func_feat, funcset_id=funset_id)


def main():
    client = bai.client.Client(BINAYRAI_TOKEN, BINAYRAI_URL)
    funset_id = bai.function.create_function_set(client)
    upload_binary(client, funset_id)
    print("[BinaryAI] BINARY_FUNCTIONSET_ID:", funset_id)


if __name__ == "__main__":
    main()
