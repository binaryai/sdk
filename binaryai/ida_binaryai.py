# coding: utf-8
import os
import json
import idaapi
import idautils
import datetime
import binaryai as bai
from ida_hexrays import DecompilationFailure
from PyQt5 import QtCore
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget
from binaryai import BinaryAIException


class IDBStore(object):
    def __init__(self, name):
        self.netn = idaapi.netnode(str(name), 0, True)

    def __getitem__(self, item):
        val = self.netn.hashval(str(item))
        if val:
            val = json.loads(val)
        return val

    def __setitem__(self, key, value):
        self.netn.hashset(str(key), json.dumps(value).encode())

    def __delitem__(self, key):
        self.netn.hashdel(str(key))


class BinaryAIMark(object):

    def __init__(self, color=0x817FFF):
        # record bai apply
        # {ea: {'name': name}}
        self.record = IDBStore("BinaryAIMark")
        self.color = color

    def add_record(self, ea, score):
        pfn = idaapi.get_func(ea)
        self.record[pfn.start_ea] = {
            'name': idaapi.get_ea_name(pfn.start_ea),
            'score': score
        }

    @staticmethod
    def set_func_name(ea, name):
        if name.startswith("sub_"):
            idaapi.set_name(ea, "", idaapi.SN_AUTO)
        else:
            idaapi.set_name(ea, name, idaapi.SN_FORCE)

    def apply_bai_func(self, ea, name, score):
        if not self.is_bai_func(ea):
            self.add_record(ea, score)
        # in private lib
        if name.startswith("sub_"):
            name = "bai_" + name
        BinaryAIMark.set_func_name(ea, name)

    def apply_bai_high_score(self, ea, name, score):
        if self.is_bai_func(ea) \
                and score <= self.record[ea]['score']:
            return False
        self.apply_bai_func(ea, name, score)
        return True

    def is_bai_func(self, ea):
        v = self.record[ea]
        return v is not None

    def revert_bai_func(self, ea):
        ea = idaapi.get_func(ea).start_ea
        if self.is_bai_func(ea):
            BinaryAIMark.set_func_name(
                ea,
                self.record[ea]['name']
            )
            del(self.record[ea])
            return True
        else:
            return False


bai_mark = BinaryAIMark()


class BinaryAIOptionsForm(idaapi.Form):
    def __init__(self, mgr):
        self.mgr = mgr
        self.token = mgr.cfg['token']
        self.funcset = mgr.cfg['funcset']
        self.form_record = {}
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
            <Token          :{itoken}>
            <Function Set   :{ifuncset}>
            ''', {
                'iretrieve_list': self.DropdownListControl(
                          items=self.retrieve_list,
                          readonly=True,
                          selval=int(not self.mgr.cfg['usepublic']),
                          width=32),
                'itopk': self.StringInput(value=str(self.mgr.cfg["topk"])),
                'ithreshold': self.StringInput(value=str(self.mgr.cfg["threshold"])),
                'iminsize': self.StringInput(value=str(self.mgr.cfg["minsize"])),
                'itoken': self.StringInput(value=self.mgr.cfg["token"]),
                'ifuncset': self.StringInput(value=self.mgr.cfg["funcset"]),
                'FormChangeCb': self.FormChangeCb(self.on_form_change)
            }
        )
        self.Compile()

    def _get_float(self, ctl):
        try:
            return float(self.GetControlValue(ctl))
        except Exception:
            return -1

    def on_form_change(self, fid):
        if fid == self.iretrieve_list.id:
            v = self.GetControlValue(self.iretrieve_list)
            self.form_record['usepublic'] = False if v else True

        if fid == self.itopk.id:
            topk = int(self._get_float(self.itopk))
            if not (0 < topk <= 15):
                topk = BinaryAIManager.Default['topk']
            self.form_record['topk'] = topk

        if fid == self.ithreshold.id:
            threshold = self._get_float(self.ithreshold)
            if not (0 < threshold <= 1):
                threshold = BinaryAIManager.Default['threshold']
            self.form_record['threshold'] = threshold

        if fid == self.iminsize.id:
            minsize = int(self._get_float(self.iminsize))
            if not (1 <= minsize <= 5):
                minsize = BinaryAIManager.Default['minsize']
            self.form_record['minsize'] = minsize

        if fid == self.itoken.id:
            self.token = self.GetControlValue(self.itoken).strip()

        if fid == self.ifuncset.id:
            self.funcset = self.GetControlValue(self.ifuncset).strip()

        return 1

    @staticmethod
    def change_options(mgr, check_token=False, check_funcset=False):
        bai_options = BinaryAIOptionsForm(mgr)
        if bai_options.Execute():
            for k, v in bai_options.form_record.items():
                mgr.cfg[k] = v

            if check_token or bai_options.token != mgr.cfg['token']:
                mgr.update_token(bai_options.token)
                if not mgr.client:
                    idaapi.warning("Wrong token!")
                    BinaryAIOptionsForm.change_options(mgr, check_token=True)
            if check_funcset or bai_options.funcset != mgr.cfg['funcset']:
                mgr.update_funcset(bai_options.funcset)
                if not mgr.funcset:
                    idaapi.warning("Wrong function set!")
                    BinaryAIOptionsForm.change_options(mgr, check_funcset=True)


class BinaryAIManager:
    Default = {
        'version': bai.__version__,
        'token': '',
        'url': 'https://api.binaryai.tencent.com/v1/endpoint',
        'funcset': '',
        'usepublic': True,
        'topk': 10,
        'minsize': 3,
        'threshold': 0.9,
        'color': "0x817FFF",
        'first_use': True
    }

    def __init__(self):
        self.name = "BinaryAI"
        cfg_dir = os.path.join(idaapi.get_user_idadir(), idaapi.CFG_SUBDIR)
        os.makedirs(cfg_dir) if not os.path.exists(cfg_dir) else None
        self.cfg = Config(os.path.join(cfg_dir, "{}.cfg".format(bai.__name__)), BinaryAIManager.Default)
        bai_mark.color = int(self.cfg['color'], 16)
        self._client = None
        self._funcset = None
        self.cview = None

    def first_use(self):
        self.cfg['funcset'] = bai.function.create_function_set(self.client)
        self._funcset = self.cfg['funcset']
        self.cfg['first_use'] = False

    @property
    def client(self):
        if self._client is None:
            try:
                self._client = bai.client.Client(self.cfg['token'], self.cfg['url'])
            except Exception:
                pass
        return self._client

    def update_token(self, token):
        self._client = None
        self.cfg['token'] = token
        self.client   # refer client to check token

    @property
    def funcset(self):
        if self.cfg['first_use']:
            self.first_use()

        if self._funcset is None:
            try:
                v = bai.function.query_function_set(self.client, self.cfg['funcset'])
                if v:
                    self._funcset = self.cfg['funcset']
            except BinaryAIException:
                pass
        return self._funcset

    def update_funcset(self, funcset):
        self._funcset = None
        self.cfg['funcset'] = funcset
        self.funcset        # refer funcset to check

    def check_before_use(self, check_funcset=False):
        if not self.client:
            idaapi.warning("Wrong token!")
            BinaryAIOptionsForm.change_options(self, check_token=True)
            return False
        if (not self.funcset) and \
                (check_funcset or not self.cfg['usepublic']):
            idaapi.warning("Wrong function set!")
            BinaryAIOptionsForm.change_options(self, check_funcset=True)
            return False
        return True

    def upload_function(self, ea, funcset_id):
        func_feat = bai.ida.get_func_feature(ea)
        func_name = idaapi.get_func_name(ea)
        hf = idaapi.hexrays_failure_t()
        cfunc = idaapi.decompile(ea, hf, idaapi.DECOMP_NO_WAIT)
        if func_feat and func_name:
            func_id = bai.function.upload_function(
                self.client, func_name, func_feat, source_code=str(cfunc), funcset_id=funcset_id)
            return func_id

    def retrieve_function(self, ea, topk, funcset_ids):
        func_id = self.upload_function(ea, None)
        if func_id:
            targets = bai.function.search_sim_funcs(self.client, func_id, funcset_ids=funcset_ids, topk=topk)
            return targets

    def retrieve_function_with_check(self, ea, topk, funcset_ids):
        succ, skip, fail = 0, 1, 2
        targets = None
        pfn = idaapi.get_func(ea)
        if idaapi.FlowChart(pfn).size < self.cfg['minsize']:
            return skip
        try:
            targets = self.retrieve_function(ea, topk=topk, funcset_ids=funcset_ids)
        except DecompilationFailure:
            pass
        except BinaryAIException as e:
            idaapi.hide_wait_box()
            assert False, "[BinaryAI] {}".format(e._msg)
        if targets is None:
            print("[{}] {} failed because get function feature error"
                  .format(self.name, idaapi.get_func_name(ea)))
            return fail
        func = targets[0]
        if func['score'] < self.cfg['threshold']:
            return skip
        if not bai_mark.apply_bai_high_score(pfn.start_ea, targets[0]['function']['name'], func['score']):
            return skip
        return succ

    def retrieve_selected_functions(self, funcs):
        if not self.check_before_use():
            return

        funcset_ids = [self.funcset] if not self.cfg['usepublic'] else None
        i, succ, skip, fail = 0, 0, 0, 0
        _funcs = [ea for ea in funcs]
        funcs_len = len(_funcs)
        idaapi.show_wait_box("Matching... (0/{})".format(funcs_len))
        for ea in _funcs:
            i += 1
            idaapi.replace_wait_box("Matching... ({}/{})".format(i, funcs_len))
            if idaapi.user_cancelled():
                idaapi.hide_wait_box()
                print("[{}] {} functions successfully matched, {} functions failed, {} functions skipped".format(
                    self.name, succ, fail, skip))
                return
            code = self.retrieve_function_with_check(ea, 1, funcset_ids)
            if code == 0:
                succ += 1
            elif code == 1:
                skip += 1
            else:
                fail += 1

        idaapi.hide_wait_box()
        print("[{}] {} functions successfully matched, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def upload_selected_functions(self, funcs):
        if not self.check_before_use(check_funcset=True):
            return
        i, succ, skip, fail = 0, 0, 0, 0
        _funcs = [ea for ea in funcs]
        funcs_len = len(_funcs)
        idaapi.show_wait_box("Uploading... (0/{})".format(funcs_len))
        for ea in _funcs:
            i += 1
            idaapi.replace_wait_box("Uploading... ({}/{})".format(i, funcs_len))
            if idaapi.user_cancelled():
                idaapi.hide_wait_box()
                print("[{}] {} functions successfully uploaded, {} functions failed, {} functions skipped".format(
                    self.name, succ, fail, skip))
                return
            pfn = idaapi.get_func(ea)
            if idaapi.FlowChart(pfn).size < self.cfg['minsize']:
                skip += 1
                continue
            func_id = None
            try:
                func_id = self.upload_function(ea, self.funcset)
            except DecompilationFailure:
                pass
            except BinaryAIException as e:
                idaapi.hide_wait_box()
                assert False, "[BinaryAI] {}".format(e._msg)
            func_name = idaapi.get_func_name(ea)
            if not func_id:
                print("[{}] {} failed because upload error".format(self.name, func_name))
                fail += 1
                continue
            succ += 1
        idaapi.hide_wait_box()
        print("[{}] {} functions successfully uploaded, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def revert_selected_functions(self, funcs):
        i, succ, skip, fail = 0, 0, 0, 0
        _funcs = [ea for ea in funcs]
        funcs_len = len(_funcs)
        idaapi.show_wait_box("reverting... (0/{})".format(funcs_len))
        for ea in _funcs:
            i += 1
            idaapi.replace_wait_box("reverting... ({}/{})".format(i, funcs_len))
            pfn = idaapi.get_func(ea)
            res = bai_mark.revert_bai_func(pfn.start_ea)
            if res:
                succ += 1
            else:
                skip += 1
        idaapi.hide_wait_box()
        print("[{}] {} functions successfully reverted, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def binaryai_callback(self, __):
        self.widget_copyright = CopyrightWindow(bai.__version__, datetime.datetime.now().year, self)
        self.widget_copyright.show()

    def retrieve_function_callback(self, __, ea=None):
        if not self.check_before_use():
            return
        funcset_ids = [self.funcset] if not self.cfg['usepublic'] else None
        func_ea = idaapi.get_screen_ea() if ea is None else ea
        func_name = idaapi.get_func_name(func_ea)
        targets = self.retrieve_function(func_ea, self.cfg['topk'], funcset_ids)
        succ, skip, fail = 0, 0, 0
        if targets is None:
            print("[{}] {} failed because get function feature error".format(self.name, func_name))
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
                    pseudo_view = idaapi.open_pseudocode(func_ea, 1)
                    pseudo_view.refresh_view(1)
                    widget = pseudo_view.toplevel
                pseudo_title = idaapi.get_widget_title(widget)

                idaapi.display_widget(self.cview.GetWidget(), idaapi.PluginForm.WOPN_DP_TAB | idaapi.PluginForm.WOPN_RESTORE)
                idaapi.set_dock_pos(self.name, pseudo_title, idaapi.DP_RIGHT)
                succ += 1
        print("[{}] {} functions successfully retrieved, {} functions failed, {} functions skipped".format(
            self.name, succ, fail, skip))

    def retrieve_all_callback(self, __):
        do_that = idaapi.ask_yn(0, "Are you sure to match all functions?")
        if do_that == 1:
            self.retrieve_selected_functions(idautils.Functions())

    def upload_function_callback(self, __, ea=None):
        if not self.check_before_use(check_funcset=True):
            return
        func_ea = idaapi.get_screen_ea() if ea is None else ea
        func_id = self.upload_function(func_ea, self.funcset)
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
            if not (k in self.cfg and self.cfg[k] is not None):
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
    target[{}] info: {}:{}
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
        self.ea = idaapi.get_func(ea).start_ea
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


class CopyrightWindow(QWidget):
    def __init__(self, ver, year, mgr):
        super(CopyrightWindow, self).__init__()
        self.mgr = mgr
        self.setWindowFlags(QtCore.Qt.WindowMinimizeButtonHint)
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
        label2.setText("(c) Copyright {}, Tencent Security KEEN Lab".format(year))
        label3.setText("<a href='https://binaryai.readthedocs.io/'>https://binaryai.readthedocs.io/</a>")
        label3.setOpenExternalLinks(True)
        label1.setAlignment(QtCore.Qt.AlignCenter)
        label2.setAlignment(QtCore.Qt.AlignCenter)
        label3.setAlignment(QtCore.Qt.AlignCenter)

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
        BinaryAIOptionsForm.change_options(self.mgr)


class UIManager:
    class UIHooks(idaapi.UI_Hooks):
        is_function_window_hooked = False

        def finish_populating_widget_popup(self, widget, popup, ctx=None):
            if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:RetrieveSelected", "BinaryAI/")
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:UploadSelected", "BinaryAI/")

                funcs = map(idaapi.getn_func, ctx.chooser_selection)
                funcs = map(lambda func: func.start_ea, funcs)
                for ea in funcs:
                    if bai_mark.is_bai_func(ea):
                        idaapi.attach_action_to_popup(widget, popup, "BinaryAI:RevertSelected", "BinaryAI/")
                        break

            if idaapi.get_widget_type(widget) == idaapi.BWN_CUSTVIEW:
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:Apply", "BinaryAI/")

        def get_chooser_item_attrs(self, chooser, n, attrs):
            func = idaapi.getn_func(n)
            if bai_mark.is_bai_func(func.start_ea):
                attrs.color = bai_mark.color

        def updating_actions(self, ctx):
            if not self.is_function_window_hooked:
                self.is_function_window_hooked = \
                    idaapi.enable_chooser_item_attrs("Functions window", True)

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
            self.mgr.revert_selected_functions(funcs)

    def apply_callback(self, ctx):
        cv = self.mgr.cview     # type: SourceCodeViewer
        bai_mark.apply_bai_func(
            cv.ea,
            cv.targets[cv.idx]['function']['name'],
            cv.targets[cv.idx]['score']
        )


def load_ida_plugin():
    if idaapi.IDA_SDK_VERSION < 730:
        return False
    if not idaapi.init_hexrays_plugin():
        return False
    if not idaapi.is_idaq():
        return False
    if not UIManager("BinaryAI").register_actions():
        return False
    return True


class Plugin(idaapi.plugin_t):
    wanted_name = "BinaryAI"
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE

    def init(self):
        if load_ida_plugin():
            return idaapi.PLUGIN_OK
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    return Plugin()
