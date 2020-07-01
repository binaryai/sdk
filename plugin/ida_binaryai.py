# coding: utf-8
import os
import json
import idc
import idaapi
import idautils
import datetime
import binaryai as bai
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget
from binaryai import BinaryAIException


class BinaryAIMark(object):
    # record bai apply
    # {ea: {'name': name, 'color': color}}
    record = {}

    @staticmethod
    def add_record(ea):
        pfn = idaapi.get_func(ea)
        BinaryAIMark.record[pfn.start_ea] = {
            'name': idaapi.get_ea_name(pfn.start_ea),
            'color': pfn.color
        }

    @staticmethod
    def apply_bai_func(ea, name, color):
        BinaryAIMark.add_record(ea)
        if name.startswith("sub_"):
            name = "bai_" + name
        idaapi.set_name(ea, name)
        idc.set_color(ea, idc.CIC_FUNC, color)

    @staticmethod
    def is_bai_func(ea):
        return idaapi.get_func(ea).start_ea in BinaryAIMark.record

    @staticmethod
    def revert_bai_func(ea):
        if BinaryAIMark.is_bai_func(ea):
            idaapi.set_name(ea, "", idaapi.SN_AUTO)
            idc.set_color(ea, idc.CIC_FUNC, BinaryAIMark.record[ea]['color'])
            BinaryAIMark.record.pop(ea)
            return True
        else:
            return False


class BinaryAIManager:
    Default = {
        'token': '',
        'url': 'https://api.binaryai.tencent.com/v1/endpoint',
        'funcset': '',
        'usepublic': True,
        'topk': 10,
        'minsize': 3,
        'threshold': 0.8,
        'color': "0x817FFF"
    }

    def __init__(self):
        self.name = "BinaryAI"
        cfg_dir = os.path.join(idaapi.get_user_idadir(), idaapi.CFG_SUBDIR)
        os.makedirs(cfg_dir) if not os.path.exists(cfg_dir) else None
        self.cfg = Config(os.path.join(cfg_dir, "{}.cfg".format(bai.__name__)), BinaryAIManager.Default)
        self._client = None
        if not self.cfg['funcset']:
            self.cfg['funcset'] = bai.function.create_function_set(self.client)
        self.cview = None

    @property
    def client(self):
        if self._client is None:
            url = self.cfg['url']
            token = self.cfg['token']
            while self._client is None:
                try:
                    self._client = bai.client.Client(token, url)
                    self.cfg['token'] = token
                except BinaryAIException as e:
                    if e._msg == "UNAUTHENTICATED: Invalid token":
                        idaapi.warning("Wrong token! Please try again.")
                        token = idaapi.ask_str("", 0, "{} Token:".format(self.name))
                        if not token:
                            assert False, "[BinaryAI] Token is not specified."
                        token = token.strip()
                    else:
                        assert False, "[BinaryAI] {}".format(e._msg)
        return self._client

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
        funcset_ids = [self.cfg['funcset']] if not self.cfg['usepublic'] else None
        i, succ, skip, fail = 0, 0, 0, 0
        _funcs = [ea for ea in funcs]
        self.widget_wait_match = WaitWindow("Matching")
        funcs_len = len(_funcs)
        for ea in _funcs:
            i += 1

            # update widget
            self.widget_wait_match.draw(i, funcs_len)

            pfn = idaapi.get_func(ea)
            func_name = idaapi.get_func_name(ea)
            if idaapi.FlowChart(pfn).size < self.cfg['minsize']:
                skip += 1
                continue
            targets = self.retrieve_function(ea, topk=1, funcset_ids=funcset_ids)
            if targets is None:
                print("[{}] {} is skipped because get function feature error".format(self.name, func_name))
                fail += 1
                continue
            func = targets[0]
            succ += 1
            if func['score'] < self.cfg['threshold']:
                continue
            BinaryAIMark.apply_bai_func(
                pfn.start_ea,
                targets[0]['function']['name'],
                int(self.cfg['color'], 16))
        self.widget_wait_match.close()
        print("[{}] {} functions successfully matched, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def upload_selected_functions(self, funcs):
        i, succ, skip, fail = 0, 0, 0, 0
        _funcs = [ea for ea in funcs]
        self.widget_wait_upload = WaitWindow("Uploading")
        funcs_len = len(_funcs)
        for ea in _funcs:
            i += 1

            # update widget
            self.widget_wait_upload.draw(i, funcs_len)

            pfn = idaapi.get_func(ea)
            if idaapi.FlowChart(pfn).size < self.cfg['minsize']:
                skip += 1
                continue
            func_id = self.upload_function(ea, self.cfg['funcset'])
            func_name = idaapi.get_func_name(ea)
            if not func_id:
                print("[{}] {} is skipped because upload error".format(self.name, func_name))
                fail += 1
                continue
            succ += 1
        self.widget_wait_upload.close()
        print("[{}] {} functions successfully uploaded, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def revert_selected_callback(self, funcs):
        i, succ, skip, fail = 0, 0, 0, 0
        _funcs = [ea for ea in funcs]
        self.widget_wait_revert = WaitWindow("Reverting")
        funcs_len = len(_funcs)
        for ea in _funcs:
            i += 1

            # update widget
            self.widget_wait_revert.draw(i, funcs_len)

            pfn = idaapi.get_func(ea)
            func_name = idaapi.get_func_name(ea)
            res = BinaryAIMark.revert_bai_func(pfn.start_ea)
            if res:
                succ += 1
            else:
                skip += 1
                print("[{}] {} is skipped because revert error".format(self.name, func_name))
        self.widget_wait_revert.close()
        print("[{}] {} functions successfully reverted, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def binaryai_callback(self, __):
        self.widget_copyright = CopyrightWindow(bai.__version__, datetime.datetime.now().year, self.cfg)
        self.widget_copyright.show()

    def retrieve_function_callback(self, __, ea=None):
        funcset_ids = [self.cfg['funcset']] if not self.cfg['usepublic'] else None
        func_ea = idaapi.get_screen_ea() if ea is None else ea
        func_name = idaapi.get_func_name(func_ea)
        targets = self.retrieve_function(func_ea, self.cfg['topk'], funcset_ids)
        succ, skip, fail = 0, 0, 0
        if targets is None:
            print("[{}] {} is skipped because get function feature error".format(self.name, func_name))
            fail += 1
        else:
            if not (self.cview and self.cview.is_alive()):
                self.cview = SourceCodeViewer(self.name)
                # CDVF_STATUSBAR 0x04, keep the status bar in the custom viewer
                idaapi.set_code_viewer_is_source(idaapi.create_code_viewer(self.cview.GetWidget(), 0x4))
            self.cview.set_user_data(func_ea, targets)

            widget = idaapi.get_current_widget()
            if idaapi.get_widget_title(widget) == self.name:
                skip += 1
            else:
                if idaapi.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
                    widget = idaapi.open_pseudocode(func_ea, 1).toplevel
                pseudo_title = idaapi.get_widget_title(widget)

                idaapi.display_widget(self.cview.GetWidget(), idaapi.PluginForm.WOPN_DP_TAB | idaapi.PluginForm.WOPN_RESTORE)
                idaapi.set_dock_pos(self.name, pseudo_title, idaapi.DP_RIGHT)
                succ += 1
        print("[{}] {} functions successfully uploaded, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def retrieve_all_callback(self, __):
        do_that = idaapi.ask_yn(0, "Are you sure to match all functions?")
        if do_that == 1:
            self.retrieve_selected_functions(idautils.Functions())

    def upload_function_callback(self, __, ea=None):
        func_ea = idaapi.get_screen_ea() if ea is None else ea
        func_id = self.upload_function(func_ea, self.cfg['funcset'])
        func_name = idaapi.get_func_name(func_ea)
        if not func_id:
            print("[{}] {} is skipped because upload error".format(self.name, func_name))
        else:
            print("[{}] {} successfully uploaded".format(self.name, func_name))

    def upload_all_callback(self, __):
        do_that = idaapi.ask_yn(0, "Are you sure to upload all functions?")
        if do_that == 1:
            self.upload_selected_functions(idautils.Functions())


class Config(dict):
    def __init__(self, path, default):
        self.path = path
        if not os.path.exists(path):
            json.dump(default, open(self.path, 'w'), indent=4)
        self.cfg = json.load(open(path))
        for k, v in default.items():
            if not (k in self.cfg and self.cfg[k]):
                self.__setitem__(k, v)

    def __getitem__(self, key):
        return self.cfg[key]

    def __setitem__(self, key, val):
        if key in self.cfg and self.cfg[key] == val:
            return
        self.cfg[key] = val
        json.dump(self.cfg, open(self.path, 'w'), indent=4)


class SourceCodeViewer(idaapi.simplecustviewer_t):
    @staticmethod
    def source_code_comment(query, func, idx=0):
        score = func["score"] if func["score"] < 1 else 1
        return """/*
    query:  {}
    target[{}]: {}
    target[{}]: {}:{}
    score:  {:6f}
*/\n""".format(query,
               idx, func['function']['name'],
               idx, func['function']['sourceFile'], func['function']['sourceLine'],
               score)

    @staticmethod
    def source_code_body(func):
        body = func['function']['sourceCode'].split("\n")
        return filter(lambda l: not l.lstrip().startswith('#'), body)

    def __init__(self, title):
        idaapi.simplecustviewer_t.__init__(self)
        self.alive = True
        self.Create(title)
        self.idx = None
        self.ea = None
        self.query = None
        self.targets = None

    def is_alive(self):
        return self.alive

    def set_user_data(self, ea, targets):
        self.idx = 0
        self.ea = ea
        self.query = idaapi.get_func_name(ea)
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


class BinaryAIOptionsForm(idaapi.Form):
    def __init__(self, cfg):
        self.cfg = cfg
        self.retrieve_list_select = 0
        self.retrieve_list = ["Public", "Private"]
        super(BinaryAIOptionsForm, self).__init__(
            r'''STARTITEM 0
BUTTON YES* OK
BinaryAI Options
            {FormChangeCb}
            <Retrieve List  :{iretrieve_list}>
            <Topk           :{itopk}>
            <Threshold      :{ithreshold}>
            <Minsize        :{iminsize}>
            BinaryAI Token  <CHANGE:{itoken}>
            Functionset ID  <CHANGE:{ifuncset}>
            ''', {
                'iretrieve_list': self.DropdownListControl(
                          items=self.retrieve_list,
                          readonly=True,
                          selval=int(not self.cfg['usepublic']),
                          width=32),
                'itopk': self.StringInput(value=str(self.cfg["topk"])),
                'ithreshold': self.StringInput(value=str(self.cfg["threshold"])),
                'iminsize': self.StringInput(value=str(self.cfg["minsize"])),
                'itoken': self.ButtonInput(self.on_change_token),
                'ifuncset': self.ButtonInput(self.on_change_funcset),
                'FormChangeCb': self.FormChangeCb(self.on_form_change)
            }
        )
        self.Compile()

    def _get_float(self, ctl):
        try:
            return float(self.GetControlValue(ctl))
        except Exception:
            return 0

    def _limit_range(self, x, min, max):
        x = max if x > max else x
        x = min if x < min else x
        return x

    def on_form_change(self, fid):
        if fid == self.iretrieve_list.id:
            v = self.GetControlValue(self.iretrieve_list)
            self.cfg['usepublic'] = False if v else True

        if fid == self.itopk.id:
            topk = int(self._get_float(self.itopk))
            topk = self._limit_range(topk, 0, 10)
            self.cfg['topk'] = topk

        if fid == self.ithreshold.id:
            threshold = self._get_float(self.ithreshold)
            threshold = self._limit_range(threshold, 0, 1)
            self.cfg['threshold'] = threshold

        if fid == self.iminsize.id:
            minsize = int(self._get_float(self.iminsize))
            minsize = self._limit_range(minsize, 0, 100)
            self.cfg['minsize'] = minsize

        return 1

    def on_change_token(self, code):
        token = idaapi.ask_str(self.cfg['token'], 0, "BinaryAI Token:")
        if token is not None:
            self.cfg['token'] = token.strip()
        return 1

    def on_change_funcset(self, code):
        funcset = idaapi.ask_str(self.cfg['funcset'], 0, "BinaryAI Function Set:")
        if funcset is not None:
            self.cfg['funcset'] = funcset.strip()
        return 1


class CopyrightWindow(QWidget):
    def __init__(self, ver, year, cfg):
        super(CopyrightWindow, self).__init__()
        self.cfg = cfg
        self.setWindowFlags(Qt.WindowMinimizeButtonHint)
        self.setFixedSize(400, 200)
        self.setWindowTitle("BinaryAI")
        layoutCopyright = QVBoxLayout()
        layoutCopyright.setSpacing(5)
        layoutButtons = QHBoxLayout()
        layoutButtons.setSpacing(10)
        mainLayout = QVBoxLayout()

        label1 = QLabel()
        label2 = QLabel()
        label3 = QLabel()

        label1.setText("BinaryAI v{}".format(ver))
        label2.setText("(c) Copyright {}, Tencent Sercurity KEEN Lab".format(year))
        label3.setText("<a href='https://binaryai.readthedocs.io/'>https://binaryai.readthedocs.io/</a>")
        label3.setOpenExternalLinks(True)
        label1.setAlignment(Qt.AlignCenter)
        label2.setAlignment(Qt.AlignCenter)
        label3.setAlignment(Qt.AlignCenter)

        btn1 = QPushButton()
        btn2 = QPushButton()
        btn1.setText("OK")
        btn2.setText("Options")
        btn1.setFixedSize(60, 20)
        btn2.setFixedSize(60, 20)
        btn1.clicked.connect(self.close)
        btn2.clicked.connect(self.showOptions)

        layoutCopyright.addWidget(label1)
        layoutCopyright.addWidget(label2)
        layoutCopyright.addWidget(label3)
        layoutButtons.addWidget(btn1)
        layoutButtons.addWidget(btn2)

        mainLayout.addLayout(layoutCopyright)
        mainLayout.addLayout(layoutButtons)

        self.setLayout(mainLayout)

    def showOptions(self):
        BinaryAIOptionsForm(self.cfg).Execute()
        return


class WaitWindow(QWidget):
    def __init__(self, operation):
        super(WaitWindow, self).__init__()
        self.operation = operation
        self.initUI()

    def initUI(self):
        self.setFixedSize(300, 100)
        self.setWindowTitle("Please wait...")

        self.layoutRetriving = QHBoxLayout()
        self.label = QLabel()
        self.label.setAlignment(Qt.AlignCenter)

        self.layoutRetriving.addWidget(self.label)
        self.setLayout(self.layoutRetriving)

        self.draw()
        self.show()

    def draw(self, cur=None, tot=None):
        if cur is None or tot is None:
            text = "{}... ".format(self.operation)
        else:
            text = "{}... ({}/{})".format(self.operation, cur, tot)
        self.label.resize(200, 50)
        self.label.setText(text)


class UIManager:
    class UIHooks(idaapi.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup, ctx=None):
            if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:RetrieveSelected", "BinaryAI/")
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:UploadSelected", "BinaryAI/")

                funcs = map(idaapi.getn_func, ctx.chooser_selection)
                funcs = map(lambda func: func.start_ea, funcs)
                for ea in funcs:
                    if BinaryAIMark.is_bai_func(ea):
                        idaapi.attach_action_to_popup(widget, popup, "BinaryAI:RevertSelected", "BinaryAI/")
                        break

            if idaapi.get_widget_type(widget) == idaapi.BWN_CUSTVIEW:
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:Apply", "BinaryAI/")

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

        UIManager.ActionHandler(self.name, self.name).register_action(self.mgr.binaryai_callback, toolbar_name)
        action = UIManager.ActionHandler("BinaryAI:About", "About", "")
        action.register_action(self.mgr.binaryai_callback, menupath=menupath)
        action = UIManager.ActionHandler("BinaryAI:RetrieveFunction", "Retrieve function", "Ctrl+Shift+d", icon=99)
        action.register_action(self.mgr.retrieve_function_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:UploadFunction", "Upload function", "", icon=97)
        action.register_action(self.mgr.upload_function_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:MatchAll", "Match all functions", "", icon=188)
        action.register_action(self.mgr.retrieve_all_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:UploadAll", "Upload all functions", "", icon=88)
        action.register_action(self.mgr.upload_all_callback, toolbar_name, menupath)

        apply_action = UIManager.ActionHandler("BinaryAI:Apply", "Apply")
        apply_action.register_action(self.apply_callback)

        retrieve_action = UIManager.ActionHandler("BinaryAI:RetrieveSelected", "Match")
        upload_action = UIManager.ActionHandler("BinaryAI:UploadSelected", "Upload")
        revert_action = UIManager.ActionHandler("BinaryAI:RevertSelected", "Revert")
        if retrieve_action.register_action(self.selected_callback) and \
                upload_action.register_action(self.selected_callback) and \
                revert_action.register_action(self.selected_callback):
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
        if ctx.action == "BinaryAI:RevertSelected":
            self.mgr.revert_selected_callback(funcs)

    def apply_callback(self, ctx):
        cv = self.mgr.cview     # type: SourceCodeViewer
        BinaryAIMark.apply_bai_func(
            cv.ea,
            cv.targets[cv.idx]['function']['name'],
            int(self.mgr.cfg['color'], 16))


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
