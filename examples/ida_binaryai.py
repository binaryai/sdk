# coding: utf-8
import idc
import idaapi
import idautils
import binaryai as bai


BINAYRAI_TOKEN = "PLEASE INPUT YOUR TOKEN HERE"
BINAYRAI_URL = "https://api.binaryai.tencent.com/v1/endpoint"


class ActionHandler(idaapi.action_handler_t):
    def __init__(self, id, name, hotkey, callback, icon=199, tooltip=""):
        idaapi.action_handler_t.__init__(self)
        self.id = id
        self.name = name
        self.hotkey = hotkey
        self.callback = callback
        self.icon = icon
        self.tooltip = tooltip

    def register_action(self):
        action_desc = idaapi.action_desc_t(self.id, self.name, self, self.hotkey, self.tooltip, self.icon)
        if not idaapi.register_action(action_desc):
            return False
        if not idaapi.attach_action_to_toolbar("SearchToolBar", self.id):
            return False
        return True

    def de_register_action(self):
        idaapi.detach_action_from_toolbar("SearchToolBar", self.id)
        idaapi.unregister_action(self.id)

    def activate(self, ctx):
        self.callback()

    def update(self, arg):
        return idaapi.AST_ENABLE_ALWAYS


class SourceCodeViewer(idaapi.simplecustviewer_t):
    @staticmethod
    def source_code_comment(query, func):
        return """/*
    query:  {}
    target: {}
    score:  {}
    id:     {}
*/\n""".format(query, func['function']['name'], func['score'], func['function']['id'])

    @staticmethod
    def source_code_body(func):
        body = func['function']['sourceCode'].split("\n")
        return filter(lambda l: not l.lstrip().startswith('#'), body)

    def __init__(self, query, targets):
        idaapi.simplecustviewer_t.__init__(self)
        self.Create("BinaryAI - {}".format(query))
        func = targets[0]
        for line in self.source_code_comment(query, func).split("\n"):
            self.AddLine(idaapi.COLSTR(line, idaapi.SCOLOR_RPTCMT))
        for line in self.source_code_body(func):
            self.AddLine(str(line))


class BinaryAIManager:
    def __init__(self, token, url):
        self.client = bai.client.Client(token, url)

    def register_actions(self):
        action1 = ActionHandler(
            'BinaryAI:queryFunction',
            '[BinaryAI] Query function',
            "Ctrl+Shift+d",
            self.query_function_callback,
            icon=199
        )
        action2 = ActionHandler(
            'BinaryAI:queryAll',
            '[BinaryAI] Query all functions',
            "Ctrl+Shift+a",
            self.query_all_callback,
            icon=188
        )
        if not action1.register_action():
            return False
        if not action2.register_action():
            return False
        return True

    def query_function(self, ea, topk=1):
        func_feat = bai.ida.get_func_feature(ea)
        func_name = idaapi.get_func_name(ea)
        if func_feat:
            func_id = bai.function.upload_function(self.client, func_name, func_feat)
            targets = bai.function.search_sim_funcs(self.client, func_id, funcset_ids=None, topk=topk)
            return targets
        return None
        

    def query_function_callback(self, threshold=0.4):
        func_ea = idaapi.get_screen_ea()
        targets = self.query_function(func_ea)
        func_name = idaapi.get_func_name(func_ea)
        if targets[0]['score'] < threshold:
            print("[BinaryAI] {} is skipped because top1_score lower than threshold({})".format(func_name, threshold))
            return
        SourceCodeViewer(func_name, targets).Show()

    def query_all_callback(self, threshold=0.8, minsize=3):
        for ea in idautils.Functions():
            pfn = idaapi.get_func(ea)
            func_name = idaapi.get_func_name(ea)
            if idaapi.FlowChart(pfn).size < minsize:
                print("[BinaryAI] {} is skipped because basicblock size lower than minsize({})".format(func_name, minsize))
                continue
            funcs = self.query_function(ea)
            if funcs is None:
                print("[BinaryAI] {} is skipped because get function feature error".format(func_name, threshold))
                continue
            func = funcs[0]              
            if func['score'] < threshold:
                print("[BinaryAI] {} is skipped because top1_score lower than threshold({})".format(func_name, threshold))
                continue
            idc.set_color(ea, idc.CIC_FUNC, 0xFFFFE1)
            idc.set_func_flags(ea, idc.get_func_flags(ea) | 0x10000)
            comment = SourceCodeViewer.source_code_comment(func_name, func)
            idaapi.set_func_cmt(pfn, comment, 0)


class BinaryAIPlugin(idaapi.plugin_t):
    comment = "BinaryAI"
    wanted_name = "BinaryAI"
    help = "BinaryAI"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        mgr = BinaryAIManager(BINAYRAI_TOKEN, BINAYRAI_URL)
        if not mgr.register_actions():
            return idaapi.PLUGIN_SKIP
        print('[BinaryAI] v{}'.format(bai.__version__))
        return idaapi.PLUGIN_OK

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    return BinaryAIPlugin()
