# coding: utf-8
import os
import json
import idaapi
import idautils
import binaryai as bai
from binaryai import BinaryAIException


class BinaryAIManager:
    Default = {
        'token': '',
        'url': '',
        'funcset': '',
        'topk': 10,
        'minsize': 3,
        'threshold': 0.8
    }

    def __init__(self):
        self.name = "BinaryAI"
        cfg_dir = os.path.join(idaapi.get_user_idadir(), idaapi.CFG_SUBDIR)
        os.makedirs(cfg_dir) if not os.path.exists(cfg_dir) else None
        self.cfg = Config(os.path.join(cfg_dir, "{}.cfg".format(bai.__name__)), BinaryAIManager.Default)
        self._client = None
        self.cview = None

    @property
    def client(self):
        if self._client is None:
            if not self.cfg['token']:
                self.cfg['token'] = idaapi.ask_str("", 0, "{} Token:".format(self.name))
            assert self.cfg['token']
            if self.cfg['url']:
                self._client = bai.client.Client(self.cfg['token'], self.cfg['url'])
            else:
                self._client = bai.client.Client(self.cfg['token'])
        return self._client

    @property
    def funcset_id(self):
        if not self.cfg['funcset']:
            self.cfg['funcset'] = bai.function.create_function_set(self.client)
        assert self.cfg['funcset']
        return self.cfg['funcset']

    def upload_function(self, ea, funcset_id):
        func_feat = bai.ida.get_func_feature(ea)
        func_name = idaapi.get_func_name(ea)
        hf = idaapi.hexrays_failure_t()
        cfunc = idaapi.decompile(ea, hf)
        if func_feat and func_name:
            func_id = bai.function.upload_function(
                self.client, func_name, func_feat, source_code=str(cfunc), funcset_id=funcset_id)
            return func_id

    def retrieve_function(self, ea, topk, funcset_ids):
        func_id = self.upload_function(ea, None)
        if func_id:
            try:
                targets = bai.function.search_sim_funcs(self.client, func_id, funcset_ids=funcset_ids, topk=topk)
            except BinaryAIException as e:
                print(e)
                if e.code == "INVALID_ARGUMENT_TOPK_EXCEED_CAPACITY":
                    return e.data['function']['similarity']
            else:
                return targets

    def retrieve_selected_functions(self, funcs):
        btn_type = idaapi.ask_yn(idaapi.ASKBTN_NO, "AUTOHIDE REGISTRY\nSearch in private functionset?")
        if btn_type == idaapi.ASKBTN_CANCEL:
            return
        funcset_ids = [self.funcset_id] if btn_type == idaapi.ASKBTN_YES else None
        for ea in funcs:
            pfn = idaapi.get_func(ea)
            func_name = idaapi.get_func_name(ea)
            if idaapi.FlowChart(pfn).size < self.cfg['minsize']:
                continue
            targets = self.retrieve_function(ea, topk=1, funcset_ids=funcset_ids)
            if targets is None:
                print("[{}] {} is skipped because get function feature error".format(self.name, func_name))
                continue
            func = targets[0]
            if func['score'] < self.cfg['threshold']:
                continue
            pfn.flags |= idaapi.FUNC_LUMINA
            idaapi.update_func(pfn)
            comment = SourceCodeViewer.source_code_comment(func_name, func)
            idaapi.set_func_cmt(pfn, comment, 0)

    def upload_selected_functions(self, funcs):
        succ, skip, fail = 0, 0, 0
        for ea in funcs:
            pfn = idaapi.get_func(ea)
            if idaapi.FlowChart(pfn).size < self.cfg['minsize']:
                skip += 1
                continue
            func_id = self.upload_function(ea, self.funcset_id)
            func_name = idaapi.get_func_name(ea)
            if not func_id:
                print("[{}] {} is skipped because upload error".format(self.name, func_name))
                fail += 1
                continue
            succ += 1
        print("[{}] {} functions successfully uploaded, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def binaryai_calllback(self, __):
        print("[{}] v{}".format(self.name, bai.__version__))

    def retrieve_function_callback(self, __, ea=None):
        btn_type = idaapi.ask_yn(idaapi.ASKBTN_NO, "AUTOHIDE REGISTRY\nSearch in private functionset?")
        if btn_type == idaapi.ASKBTN_CANCEL:
            return
        funcset_ids = [self.funcset_id] if btn_type == idaapi.ASKBTN_YES else None
        func_ea = idaapi.get_screen_ea() if ea is None else ea
        func_name = idaapi.get_func_name(func_ea)
        targets = self.retrieve_function(func_ea, self.cfg['topk'], funcset_ids)
        if targets is None:
            print("[{}] {} is skipped because get function feature error".format(self.name, func_name))
            return

        if not (self.cview and self.cview.is_alive()):
            self.cview = SourceCodeViewer(self.name)
            # CDVF_STATUSBAR 0x04, keep the status bar in the custom viewer
            idaapi.set_code_viewer_is_source(idaapi.create_code_viewer(self.cview.GetWidget(), 0x4))
        self.cview.set_user_data(func_name, targets)

        widget = idaapi.get_current_widget()
        if idaapi.get_widget_title(widget) == self.name:
            return

        if idaapi.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
            widget = idaapi.open_pseudocode(func_ea, 1).toplevel
        pseudo_title = idaapi.get_widget_title(widget)

        idaapi.display_widget(self.cview.GetWidget(), idaapi.PluginForm.WOPN_DP_TAB | idaapi.PluginForm.WOPN_RESTORE)
        idaapi.set_dock_pos(self.name, pseudo_title, idaapi.DP_RIGHT)
        return

    def retrieve_all_callback(self, __):
        self.retrieve_selected_functions(idautils.Functions())

    def upload_function_callback(self, __, ea=None):
        func_ea = idaapi.get_screen_ea() if ea is None else ea
        func_id = self.upload_function(func_ea, self.funcset_id)
        func_name = idaapi.get_func_name(func_ea)
        if not func_id:
            print("[{}] {} is skipped because upload error".format(self.name, func_name))
        else:
            print("[{}] {} successfully uploaded".format(self.name, func_name))

    def upload_all_callback(self, __):
        self.upload_selected_functions(idautils.Functions())


class Config(dict):
    def __init__(self, path, default):
        self.path = path
        if not os.path.exists(path):
            json.dump(default, open(self.path, 'w'), indent=4)
        self.cfg = json.load(open(path))

    def __getitem__(self, key):
        return self.cfg[key]

    def __setitem__(self, key, val):
        self.cfg[key] = val
        json.dump(self.cfg, open(self.path, 'w'), indent=4)


class SourceCodeViewer(idaapi.simplecustviewer_t):
    @staticmethod
    def source_code_comment(query, func, idx=0):
        return """/*
    query:  {}
    target[{}]: {}
    score:  {}
*/\n""".format(query, idx, func['function']['name'], func['score'])

    @staticmethod
    def source_code_body(func):
        body = func['function']['sourceCode'].split("\n")
        return filter(lambda l: not l.lstrip().startswith('#'), body)

    def __init__(self, title):
        idaapi.simplecustviewer_t.__init__(self)
        self.alive = True
        self.Create(title)

    def is_alive(self):
        return self.alive

    def set_user_data(self, query, targets):
        self.idx = 0
        self.query = query
        self.targets = targets
        self._repaint()

    def _repaint(self):
        self.ClearLines()
        func = self.targets[self.idx]
        for line in self.source_code_comment(self.query, func, self.idx).split("\n"):
            self.AddLine(idaapi.COLSTR(line, idaapi.SCOLOR_RPTCMT))
        for line in self.source_code_body(func):
            self.AddLine(str(line))
        self.Refresh()

    def OnClose(self):
        self.alive = False

    def OnKeydown(self, vkey, shift):
        if shift == 0 and vkey == ord("K"):
            self.idx = (self.idx + len(self.targets) - 1) % len(self.targets)
            self._repaint()
        elif shift == 0 and vkey == ord("J"):
            self.idx = (self.idx + 1) % len(self.targets)
            self._repaint()


class UIManager:
    class UIHooks(idaapi.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:RetrieveSelected", "BinaryAI/")
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:UploadSelected", "BinaryAI/")

    class ActionHandler(idaapi.action_handler_t):
        def __init__(self, name, label, shortcut=None, tooltip=None, icon=-1, flags=0):
            idaapi.action_handler_t.__init__(self)
            self.name = name
            self.action_desc = idaapi.action_desc_t(name, label, self, shortcut, tooltip, icon, flags)

        def register_action(self, callback, toolbar_name=None, menupath=None):
            self.callback = callback
            if not idaapi.register_action(self.action_desc):
                return False
            if toolbar_name and not idaapi.attach_action_to_toolbar(toolbar_name, self.name):
                return False
            if menupath and not idaapi.attach_action_to_menu(menupath, self.name, idaapi.SETMENU_APP):
                return False
            return True

        def activate(self, ctx):
            self.callback(ctx)

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    def __init__(self, name):
        self.name = name
        self.mgr = BinaryAIManager()
        self.hooks = UIManager.UIHooks()

    def register_actions(self):
        toolbar_name, menupath = self.name, self.name
        idaapi.create_toolbar(toolbar_name, self.name)
        idaapi.create_menu(menupath, self.name, "Help")

        UIManager.ActionHandler(self.name, self.name).register_action(self.mgr.binaryai_calllback, toolbar_name)
        action = UIManager.ActionHandler("BinaryAI:RetrieveFunction", "Retrieve function", "Ctrl+Shift+d", icon=99)
        action.register_action(self.mgr.retrieve_function_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:RetrieveAll", "Retrieve all functions", "", icon=188)
        action.register_action(self.mgr.retrieve_all_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:UploadFunction", "Upload function", "", icon=97)
        action.register_action(self.mgr.upload_function_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:UploadAll", "Upload all functions", "", icon=88)
        action.register_action(self.mgr.upload_all_callback, toolbar_name, menupath)

        retrieve_action = UIManager.ActionHandler("BinaryAI:RetrieveSelected", "Retrieve")
        upload_action = UIManager.ActionHandler("BinaryAI:UploadSelected", "Upload")
        if retrieve_action.register_action(self.selected_callback) and \
                upload_action.register_action(self.selected_callback):
            self.hooks.hook()
            return True
        return False

    def selected_callback(self, ctx):
        funcs = map(idaapi.getn_func, ctx.chooser_selection)
        funcs = map(lambda func: func.start_ea, funcs)
        if ctx.action == "BinaryAI:RetrieveSelected":
            self.mgr.retrieve_selected_functions(funcs)
        if ctx.action == "BinaryAI:UploadSelected":
            self.mgr.upload_selected_functions(funcs)


class Plugin(idaapi.plugin_t):
    wanted_name = "BinaryAI"
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE

    def init(self):
        if idaapi.init_hexrays_plugin():
            mgr = UIManager(Plugin.wanted_name)
            if mgr.register_actions():
                return idaapi.PLUGIN_OK
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    return Plugin()
