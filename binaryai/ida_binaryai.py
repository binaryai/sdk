# coding: utf-8
import idc
import idaapi
import ida_auto


if idaapi.IDA_SDK_VERSION < 730:
    print("[BinaryAI] Need IDA >= 730")
    if not idaapi.is_idaq():
        idc.qexit(1)            # save idb
    else:
        assert 0, "IDA version should be at least 7.3"


import os
import platform
import json
import idautils
import datetime
import binaryai as bai
from PyQt5 import QtCore
from ida_hexrays import DecompilationFailure
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget
from binaryai import BinaryAIException


class BinaryAILog(object):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    level = INFO
    name = "BinaryAI"

    @staticmethod
    def log(level, msg, *args, **kwargs):
        if level >= BinaryAILog.level:
            if args:
                for v in args:
                    msg += str(args)
            if kwargs:
                msg += str(kwargs)

            print("[{}] {}".format(BinaryAILog.name, msg))

    @staticmethod
    def debug(msg, *args, **kwargs):
        BinaryAILog.log(BinaryAILog.DEBUG,
                        msg, *args, **kwargs)

    @staticmethod
    def skip(func_name, reason):
        BinaryAILog.log(BinaryAILog.INFO,
                        "{} is skipped because {}.".format(
                            func_name, reason))

    @staticmethod
    def fail(func_name, reason):
        BinaryAILog.log(BinaryAILog.WARN,
                        "{} failed because {}.".format(
                            func_name, reason))

    @staticmethod
    def success(func_name, status):
        BinaryAILog.log(BinaryAILog.INFO,
                        "{} successfully {}.".format(
                            func_name, status))

    @staticmethod
    def summary(succ, skip, fail, status):
        BinaryAILog.log(BinaryAILog.INFO,
                        "{} successfully {}, {} skipped, {} failed".format(
                            succ, status, skip, fail))

    @staticmethod
    def fatal(e):
        assert False, "[{}] {}".format(BinaryAILog.name, str(e))


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


class BinaryAIConfig(Config):
    Default = {
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

    def __init__(self, path=None, default=None):
        if path is None:
            path = os.path.join(idaapi.get_user_idadir(), idaapi.CFG_SUBDIR)
            if not os.path.exists(path):
                os.makedirs(path)
            path = os.path.join(path, "binaryai.cfg")
        if default is None:
            default = BinaryAIConfig.Default

        super(BinaryAIConfig, self).__init__(path, default)


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

    def __init__(self):
        # record bai apply
        # {ea: {'name': name, 'score': score}
        self.record = IDBStore("BinaryAIMark")

    def add_record(self, ea, score):
        pfn = idaapi.get_func(ea)
        self.record[pfn.start_ea] = {
            'name': idaapi.get_ea_name(pfn.start_ea),
            'score': score
        }

    def is_bai_func(self, ea):
        v = self.record[ea]
        return v is not None

    @staticmethod
    def set_func_name(ea, name):
        if name.startswith("sub_"):
            idaapi.set_name(ea, "", idaapi.SN_AUTO)
        else:
            idaapi.set_name(ea, str(name), idaapi.SN_FORCE)

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

    def revert_bai_func(self, ea):
        ea = idaapi.get_func(ea).start_ea
        if self.is_bai_func(ea):
            BinaryAIMark.set_func_name(
                ea,
                self.record[ea]['name']
            )
            del (self.record[ea])
            return True
        else:
            return False


"""global resource"""
bai_config = BinaryAIConfig()
bai_mark = BinaryAIMark()


class BinaryAIManager(object):
    def __init__(self):
        self.name = "BinaryAI"
        self._client = None
        self._funcset = None

    @property
    def client(self):
        if self._client is None:
            try:
                self._client = bai.client.Client(bai_config['token'], bai_config['url'])
            except Exception:
                pass
        return self._client

    def update_token(self, token):
        self._client = None
        bai_config['token'] = token
        return self.client is not None

    @property
    def funcset(self):
        if bai_config['first_use']:
            self._funcset = bai.function.create_function_set(self.client)
            if self._funcset:
                bai_config['first_use'] = False

        if self._funcset is None:
            try:
                if bai.function.query_function_set(self.client, bai_config['funcset']):
                    self._funcset = bai_config['funcset']
            except BinaryAIException:
                pass
        return self._funcset

    def update_funcset(self, funcset):
        self._funcset = None
        bai_config['funcset'] = funcset
        return self.funcset is None

    def retrieve(self, ea, topk, funcset_ids, flag=1):
        func_id = self.upload(ea, None)
        if func_id:
            targets = bai.function.search_sim_funcs(self.client, func_id, funcset_ids=funcset_ids, topk=topk)
            if flag == 2:
                return targets, func_id
            return targets
        return None

    def upload(self, ea, funcset_id):
        func_feat = bai.ida.get_func_feature(ea)
        func_name = idaapi.get_func_name(ea)
        hf = idaapi.hexrays_failure_t()
        cfunc = idaapi.decompile(ea, hf, idaapi.DECOMP_NO_WAIT)
        if func_feat and func_name:
            func_id = bai.function.upload_function(
                self.client, func_name, func_feat, source_code=str(cfunc), funcset_id=funcset_id)
            return func_id
        return None


class SourceCodeViewer(object):
    class SourceCodeViewerUI(idaapi.simplecustviewer_t):
        def __init__(self, title):
            idaapi.simplecustviewer_t.__init__(self)
            self.ea = None
            self.query = None
            self.idx = None
            self.targets = None
            self.title = title
            self.Create(title)
            idaapi.set_code_viewer_is_source(idaapi.create_code_viewer(self.GetWidget(), 0x4))

        def set_user_data(self, ea, targets):
            self.idx = 0
            self.ea = idaapi.get_func(ea).start_ea
            self.query = idaapi.get_func_name(ea)
            self.targets = targets
            self._repaint()

        def _repaint(self):
            self.ClearLines()
            func = self.targets[self.idx]
            for line in SourceCodeViewer.source_code_comment(self.query, func, self.idx).split("\n"):
                self.AddLine(idaapi.COLSTR(line, idaapi.SCOLOR_RPTCMT))
            for line in SourceCodeViewer.source_code_body(func):
                self.AddLine(str(line))
            self.Refresh()

        def Show(self):
            widget = idaapi.get_current_widget()
            if idaapi.get_widget_title(widget) != self.title:
                if idaapi.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
                    pseudo_view = idaapi.open_pseudocode(self.ea, 1)
                    pseudo_view.refresh_view(1)
                    widget = pseudo_view.toplevel
                pseudo_title = idaapi.get_widget_title(widget)

                idaapi.display_widget(self.GetWidget(),
                                      idaapi.PluginForm.WOPN_DP_TAB | idaapi.PluginForm.WOPN_RESTORE)
                idaapi.set_dock_pos(self.title, pseudo_title, idaapi.DP_RIGHT)

        def OnKeydown(self, vkey, shift):
            if shift == 0 and vkey == ord("K"):
                self.idx = (self.idx + len(self.targets) - 1) % len(self.targets)
                self._repaint()
            elif shift == 0 and vkey == ord("J"):
                self.idx = (self.idx + 1) % len(self.targets)
                self._repaint()

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
        self.view = None  # type: SourceCodeViewer.SourceCodeViewerUI
        self.title = title

    def is_visible(self):
        return self.view and self.view.GetWidget()

    def set_user_data(self, ea, targets):
        if not self.is_visible():
            self.view = SourceCodeViewer.SourceCodeViewerUI(self.title)
        self.view.set_user_data(ea, targets)
        self.view.Show()

    def get_current_info(self):
        return self.view.ea, \
               self.view.targets[self.view.idx]['function']['name'], \
               self.view.targets[self.view.idx]['score']


class BinaryAIOptionsForm(idaapi.Form):
    def __init__(self, mgr):
        self.mgr = mgr
        self.token = bai_config['token']
        self.funcset = bai_config['funcset']
        self.form_record = {}
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
                    selval=int(not bai_config['usepublic']),
                    width=32),
                'itopk': self.StringInput(value=str(bai_config["topk"])),
                'ithreshold': self.StringInput(value=str(bai_config["threshold"])),
                'iminsize': self.StringInput(value=str(bai_config["minsize"])),
                'itoken': self.StringInput(value=bai_config["token"]),
                'ifuncset': self.StringInput(value=bai_config["funcset"]),
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
                topk = BinaryAIConfig.Default['topk']
            self.form_record['topk'] = topk

        if fid == self.ithreshold.id:
            threshold = self._get_float(self.ithreshold)
            if not (0 < threshold <= 1):
                threshold = BinaryAIConfig.Default['threshold']
            self.form_record['threshold'] = threshold

        if fid == self.iminsize.id:
            minsize = int(self._get_float(self.iminsize))
            if not (1 <= minsize <= 5):
                minsize = BinaryAIConfig.Default['minsize']
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
                bai_config[k] = v

            if check_token or bai_options.token != bai_config['token']:
                mgr.update_token(bai_options.token)
                if not mgr.client:
                    idaapi.warning("Wrong token!")
                    BinaryAIOptionsForm.change_options(mgr, check_token=True)
            if check_funcset or bai_options.funcset != bai_config['funcset']:
                mgr.update_funcset(bai_options.funcset)
                if not mgr.funcset:
                    idaapi.warning("Wrong function set!")
                    BinaryAIOptionsForm.change_options(mgr, check_funcset=True)


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


class BinaryAIOperations(object):
    def __init__(self, mgr):
        self.mgr = mgr  # type: BinaryAIManager

    def check_before_use(self, check_funcset=False):
        if not self.mgr.client:
            idaapi.warning("Wrong token!")
            BinaryAIOptionsForm.change_options(self.mgr, check_token=True)
            return False
        if (not self.mgr.funcset) and \
                (check_funcset or not bai_config['usepublic']):
            idaapi.warning("Wrong function set!")
            BinaryAIOptionsForm.change_options(self.mgr, check_funcset=True)
            return False
        return True

    def retrieve(self, ea, cview):
        if not self.check_before_use():
            return
        func_name = idaapi.get_func_name(ea)
        funcset_ids = [self.mgr.funcset] if not bai_config['usepublic'] else None

        targets = None
        try:
            targets = self.mgr.retrieve(ea, bai_config['topk'], funcset_ids)
        except DecompilationFailure as e:
            BinaryAILog.fail(idaapi.get_func_name(ea), str(e))
        except BinaryAIException as e:
            BinaryAILog.fatal(e)

        if targets is None:
            BinaryAILog.skip(func_name, "get function feature error")
            return

        cview.set_user_data(ea, targets)

    def _match_with_check(self, ea, topk, funcset_ids):
        fail, skip, succ = -1, 0, 1
        # < minsize
        pfn = idaapi.get_func(ea)
        if idaapi.FlowChart(pfn).size < bai_config['minsize']:
            return skip
        # do match
        try:
            targets = self.mgr.retrieve(ea, topk=1, funcset_ids=funcset_ids)
        except DecompilationFailure as e:
            BinaryAILog.fail(idaapi.get_func_name(ea), str(e))
            return fail
        except BinaryAIException as e:
            idaapi.hide_wait_box()
            BinaryAILog.fatal(e)
        if targets is None:
            return fail
        if targets[0]['score'] < bai_config['threshold']:
            return skip
        if not bai_mark.apply_bai_high_score(
                ea,
                targets[0]['function']['name'],
                targets[0]['score']):
            return skip
        return succ

    def match_funcs(self, funcs):
        if not self.check_before_use():
            return

        i, fail, skip, succ = 0, 0, 0, 0

        def stop():
            idaapi.hide_wait_box()
            BinaryAILog.summary(succ, skip, fail, "matched")

        funcs_len = len(funcs)
        idaapi.show_wait_box("Matching... (0/{})".format(funcs_len))
        funcset_ids = [self.mgr.funcset] if not bai_config['usepublic'] else None
        for ea in funcs:
            # refresh process status
            i += 1
            idaapi.replace_wait_box("Matching... ({}/{})".format(i, funcs_len))
            # check cancelled or not
            if idaapi.user_cancelled():
                stop()
                return
            status = self._match_with_check(ea, bai_config['topk'], funcset_ids)
            if status == 1:
                succ += 1
            elif status == 0:
                skip += 1
            else:
                fail += 1
        stop()

    def upload(self, ea):
        if not self.check_before_use(check_funcset=True):
            return
        func_id = None
        try:
            func_id = self.mgr.upload(ea, self.mgr.funcset)
        except DecompilationFailure as e:
            BinaryAILog.fail(idaapi.get_func_name(ea), str(e))
        except BinaryAIException as e:
            BinaryAILog.fatal(e)

        if func_id:
            BinaryAILog.success(idaapi.get_func_name(ea), "uploaded")

    def upload_funcs(self, funcs):
        if not self.check_before_use(check_funcset=True):
            return

        i, succ, skip, fail = 0, 0, 0, 0

        def stop():
            idaapi.hide_wait_box()
            BinaryAILog.summary(succ, skip, fail, "uploaded")

        funcs_len = len(funcs)
        idaapi.show_wait_box("Uploading... (0/{})".format(funcs_len))
        for ea in funcs:
            i += 1
            idaapi.replace_wait_box("Uploading... ({}/{})".format(i, funcs_len))

            if idaapi.user_cancelled():
                stop()
                return
            # < minsize
            pfn = idaapi.get_func(ea)
            if idaapi.FlowChart(pfn).size < bai_config['minsize']:
                skip += 1
                continue
            # try upload
            func_id = None
            try:
                func_id = self.mgr.upload(ea, self.mgr.funcset)
            except DecompilationFailure as e:
                BinaryAILog.fail(idaapi.get_func_name(ea), str(e))
                fail += 1
                continue
            except BinaryAIException as e:
                stop()
                BinaryAILog.fatal(e)
            # fail
            if not func_id:
                fail += 1
                continue
            succ += 1
        stop()

    def apply(self, cview):
        ea, name, score = cview.get_current_info()
        bai_mark.apply_bai_func(ea, name, score)

    def revert_funcs(self, funcs):
        i, succ, skip = 0, 0, 0

        def stop():
            idaapi.hide_wait_box()
            BinaryAILog.summary(succ, skip, 0, "reverted")

        funcs_len = len(funcs)
        idaapi.show_wait_box("Reverting... (0/{})".format(funcs_len))
        for ea in funcs:
            i += 1
            idaapi.replace_wait_box("Reverting... ({}/{})".format(i, funcs_len))

            if idaapi.user_cancelled():
                stop()
                return

            if bai_mark.revert_bai_func(ea):
                succ += 1
            else:
                skip += 1
        stop()


class UIManager:
    class UIHooks(idaapi.UI_Hooks):
        is_function_window_hooked = False

        def finish_populating_widget_popup(self, widget, popup, ctx=None):
            if idaapi.get_widget_type(widget) == idaapi.BWN_FUNCS:
                idaapi.attach_action_to_popup(widget, popup, "BinaryAI:MatchSelected", "BinaryAI/")
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
                attrs.color = int(bai_config['color'], 16)

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

    def __init__(self, name, bai_mgr):
        self.name = name
        self.bai_mgr = bai_mgr
        self.operations = BinaryAIOperations(bai_mgr)
        self.cview = SourceCodeViewer(self.name)
        self.hooks = UIManager.UIHooks()
        self.about_window = None

    def register_actions(self):
        toolbar_name, menupath = self.name, self.name
        idaapi.create_toolbar(toolbar_name, self.name)
        idaapi.create_menu(menupath, self.name, "Help")

        UIManager.ActionHandler(self.name, self.name).register_action(self.binaryai_callback, toolbar_name)
        action = UIManager.ActionHandler("BinaryAI:About", "About", "")
        action.register_action(self.binaryai_callback, menupath=menupath)
        action = UIManager.ActionHandler("BinaryAI:RetrieveFunction", "Retrieve function", "Ctrl+Shift+d", icon=99)
        action.register_action(self.retrieve_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:UploadFunction", "Upload function", "", icon=97)
        action.register_action(self.upload_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:MatchAll", "Match all functions", "", icon=188)
        action.register_action(self.match_all_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:UploadAll", "Upload all functions", "", icon=88)
        action.register_action(self.upload_all_callback, toolbar_name, menupath)

        apply_action = UIManager.ActionHandler("BinaryAI:Apply", "Apply")
        apply_action.register_action(self.apply_callback)

        match_action = UIManager.ActionHandler("BinaryAI:MatchSelected", "Match")
        upload_action = UIManager.ActionHandler("BinaryAI:UploadSelected", "Upload")
        revert_action = UIManager.ActionHandler("BinaryAI:RevertSelected", "Revert")
        if match_action.register_action(self.selected_callback) and \
                upload_action.register_action(self.selected_callback) and \
                revert_action.register_action(self.selected_callback):
            self.hooks.hook()
            return True
        return False

    def binaryai_callback(self, ctx):
        self.about_window = CopyrightWindow(bai.__version__, datetime.datetime.now().year, self.bai_mgr)
        self.about_window.show()

    def retrieve_callback(self, ctx, ea=None):
        func_ea = idaapi.get_screen_ea() if ea is None else ea
        self.operations.retrieve(func_ea, self.cview)

    def match_all_callback(self, ctx):
        self.operations.match_funcs(list(idautils.Functions()))

    def upload_callback(self, ctx):
        self.operations.upload(idaapi.get_screen_ea())

    def upload_all_callback(self, ctx):
        self.operations.upload_funcs(list(idautils.Functions()))

    def selected_callback(self, ctx):
        funcs = map(idaapi.getn_func, ctx.chooser_selection)
        funcs = [func.start_ea for func in funcs]
        if ctx.action == "BinaryAI:MatchSelected":
            self.operations.match_funcs(funcs)
        if ctx.action == "BinaryAI:UploadSelected":
            self.operations.upload_funcs(funcs)
        if ctx.action == "BinaryAI:RevertSelected":
            self.operations.revert_funcs(funcs)

    def apply_callback(self, ctx):
        self.operations.apply(self.cview)


def check_decompiler():
    if not idaapi.init_hexrays_plugin():
        BinaryAILog.log(BinaryAILog.ERROR, "Hex-Rays decompiler not exists")
        return False
    return True


class BinaryAIIDAPlugin(idaapi.plugin_t):
    wanted_name = "BinaryAI"
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE

    def init(self):
        if not idaapi.is_idaq():
            BinaryAILog.log(BinaryAILog.INFO, "Plugin should be loaded in idaq mode")
            return idaapi.PLUGIN_SKIP
        if check_decompiler():
            bai_mgr = BinaryAIManager()
            ui_mgr = UIManager(BinaryAIIDAPlugin.wanted_name, bai_mgr)
            if ui_mgr.register_actions():
                return idaapi.PLUGIN_OK
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    BinaryAILog.level = BinaryAILog.DEBUG
    return BinaryAIIDAPlugin()


def get_user_idadir():
    system = platform.system()
    if system == 'Windows':
        return os.path.join(os.getenv('APPDATA'), "Hex-Rays", "IDA Pro")
    elif system in ['Linux', 'Darwin']:
        return os.path.join(os.getenv('HOME'), ".idapro")
    else:
        return ""


def cmd_upload(funcset=bai_config['funcset']):
    succ = 0
    bai_mgr = BinaryAIManager()
    for ea in idautils.Functions():
        try:
            bai_mgr.upload(ea, funcset)
            succ += 1
        except Exception:
            continue
    return succ


def cmd_match(funcset_ids=None):
    bai_mgr = BinaryAIManager()
    output_json = {}
    for ea in idautils.Functions():
        pfn = idaapi.get_func(ea)
        if idaapi.FlowChart(pfn).size < bai_config['minsize']:
            BinaryAILog.skip(idaapi.get_func_name(ea), 'size < minsize')
            continue
        try:
            targets, func_id = bai_mgr.retrieve(ea, 1, funcset_ids, 2)
        except Exception as e:
            print(str(e))
            continue

        if targets and func_id:
            if targets[0]['score'] < bai_config['threshold']:
                continue
            bai_mark.apply_bai_high_score(
                ea,
                targets[0]['function']['name'],
                targets[0]['score'])
        cur_json = {'id': func_id, 'score': targets[0]['score'],
                    'target': {'id': targets[0]['function']['id'], 'name': targets[0]['function']['name']}}
        output_json[str(ea)] = cur_json
    path = os.path.join(get_user_idadir(), "output.json")
    with open(path, "w") as f:
        f.write(str(json.dumps(output_json, sort_keys=True, indent=2)))
        f.close()


if __name__ == "__main__":
    ida_auto.auto_wait()
    retcode = 0
    if check_decompiler():
        if idc.ARGV[1] == '1':
            cmd_upload(*idc.ARGV[2:])
        if idc.ARGV[1] == '2':
            cmd_match()
    else:
        retcode = 1
    idaapi.qexit(retcode)
