# coding: utf-8
import os
import json
import datetime

import idaapi
import idautils
from PyQt5 import QtCore
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QWidget

import binaryai as bai
from binaryai import BinaryAIException, BinaryAIConfig, BinaryAILog


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


# global resource
bai_config = BinaryAIConfig(os.path.join(idaapi.get_user_idadir(), idaapi.CFG_SUBDIR))
bai_mark = BinaryAIMark()


class BinaryAIManager(object):
    def __init__(self):
        self.name = "BinaryAI"
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                self._client = bai.client.Client(bai_config['token'], bai_config['url'])
            except Exception as e:
                print(str(e))
        return self._client

    def update_token(self, token):
        self._client = None
        bai_config['token'] = token
        return self.client is not None

    def retrieve(self, ea, topk, flag=1):
        func_id = self.upload(ea)
        if func_id:
            targets = bai.function.search_sim_funcs(self.client, func_id, topk=topk)
            if flag == 2:
                return targets, func_id
            return targets
        return None

    def retrieve_by_feature(self, ea, topk):
        feat = bai.ida.get_func_feature(ea)
        if feat:
            targets = bai.function.search_sim_funcs(self.client, feature=feat, topk=topk)
            return targets
        return None

    def upload(self, ea, funcset=None):
        func = bai.ida.get_upload_func_info(ea)
        if func is None:
            return None

        func_id = bai.function.upload_function(
            self.client, func['name'], func['feature'],
            source_code=None, source_file=None, source_line=None,
            binary_file=func['binary_file'], binary_sha256=func['binary_sha256'], fileoffset=func['binary_offset'],
            _bytes=func['func_bytes'], platform=func['platform'], throw_duplicate_error=False,
            pseudo_code=func['pseudo_code'], package_name=None)

        if funcset and func_id:
            bai.function.saveto_function_set_members(self.client, funcset, [func_id])
        return func_id


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

                if idaapi.IDA_SDK_VERSION >= 730:
                    idaapi.display_widget(self.GetWidget(), idaapi.PluginForm.WOPN_DP_TAB | idaapi.PluginForm.WOPN_RESTORE)
                else:
                    idaapi.display_widget(self.GetWidget(), idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_RESTORE)

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
        comment = '/*\n'
        comment += "query:  {}\n".format(query)
        comment += "score:  {:6f}\n".format(score)

        comment += "target[{}]: {}\n".format(idx, func['function']['name'])
        packagename = func['function']['sourceCodeInfo']['packagename']
        if packagename is not None:
            comment += "package name: {}\n".format(packagename)
        sourcefile = func['function']['sourceCodeInfo']['filename']
        linenumber = func['function']['sourceCodeInfo']['linenumber']
        if sourcefile is not None:
            comment += "target[{}] sourceInfo: {}:{}\n".format(idx, sourcefile, linenumber)
        binaryfile = func['function']['binaryInfo']['filename']
        fileoffset = func['function']['binaryInfo']['fileoffset']
        fileoffset = fileoffset if fileoffset is not None else 0
        platform = func['function']['binaryInfo']['platform']
        sha256 = func['function']['binaryInfo']['sha256']
        if binaryfile is not None:
            comment += "target[{}] binaryInfo: {}:{}, {}, {}\n".format(idx, binaryfile, hex(fileoffset), platform, sha256)

        comment += "*/\n"
        return comment

    @staticmethod
    def source_code_body(func):
        if func['function']['sourceCodeInfo']['code']:
            code = func['function']['sourceCodeInfo']['code']
        else:
            code = func['function']['sourceCodeInfo']['pseudocode']
        if code is None:
            body = ["/* Source Code is not available for this function */"]
        else:
            body = code.split("\n")
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
        self.form_record = {}

        retrieveListLabel = "Official Function Database"
        if self.token and mgr.client:
            total_count = bai.function.query_retrieve_list_count(mgr.client)
            if total_count != 0:
                retrieveListLabel = "Private Function Database({} functions)".format(total_count)

        super(BinaryAIOptionsForm, self).__init__(
            r'''STARTITEM 0
BUTTON YES* OK
BinaryAI Options
            {FormChangeCb}
            RetrieveList   {iretrieve_list}
            <Topk           :{itopk}>
            <Threshold      :{ithreshold}>
            <Minsize        :{iminsize}>
            <Token          :{itoken}>
            ''', {
                'iretrieve_list': self.StringLabel(retrieveListLabel),
                'itopk': self.StringInput(value=str(bai_config["topk"])),
                'ithreshold': self.StringInput(value=str(bai_config["threshold"])),
                'iminsize': self.StringInput(value=str(bai_config["minsize"])),
                'itoken': self.StringInput(value=bai_config["token"]),
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
        if fid == self.itopk.id:
            topk = int(self._get_float(self.itopk))
            self.form_record['topk'] = topk

        if fid == self.ithreshold.id:
            threshold = self._get_float(self.ithreshold)
            if not (0 < threshold <= 1):
                threshold = BinaryAIConfig.Default['threshold']
            self.form_record['threshold'] = threshold

        if fid == self.iminsize.id:
            minsize = int(self._get_float(self.iminsize))
            self.form_record['minsize'] = minsize

        if fid == self.itoken.id:
            self.token = self.GetControlValue(self.itoken).strip()

        return 1

    @staticmethod
    def change_options(mgr, check_token=False):
        bai_options = BinaryAIOptionsForm(mgr)
        if bai_options.Execute():
            for k, v in bai_options.form_record.items():
                bai_config[k] = v

            if check_token or bai_options.token != bai_config['token']:
                mgr.update_token(bai_options.token)
                if not mgr.client:
                    idaapi.warning("Wrong token!")
                    BinaryAIOptionsForm.change_options(mgr, check_token=True)


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
    mgr = None

    def __init__(self, mgr):
        assert(isinstance(mgr, BinaryAIManager))
        self.mgr = mgr

    def check_before_use(self):
        if not self.mgr.client:
            idaapi.warning("Wrong Options!")
            BinaryAIOptionsForm.change_options(self.mgr, check_token=True)
            return False
        return True

    def retrieve(self, ea, cview):
        if not self.check_before_use():
            return
        func_name = idaapi.get_func_name(ea)

        try:
            targets = self.mgr.retrieve_by_feature(ea, bai_config['topk'])
        except idaapi.DecompilationFailure as e:
            BinaryAILog.fail(idaapi.get_func_name(ea), str(e))
        except BinaryAIException as e:
            BinaryAILog.fatal(e)

        if targets is None:
            BinaryAILog.skip(func_name, "get function feature error")
            return

        if len(targets) == 0:
            idaapi.warning("No similar function found!")
            return

        cview.set_user_data(ea, targets)

    def _match_with_check(self, ea):
        fail, skip, succ = -1, 0, 1
        # < minsize
        pfn = idaapi.get_func(ea)
        if idaapi.FlowChart(pfn).size < bai_config['minsize']:
            return skip
        # do match
        try:
            targets = self.mgr.retrieve_by_feature(ea, topk=1)
        except idaapi.DecompilationFailure as e:
            BinaryAILog.fail(idaapi.get_func_name(ea), str(e))
            return fail
        except BinaryAIException as e:
            idaapi.hide_wait_box()
            BinaryAILog.fatal(e)
        if targets is None:
            return fail
        if targets[0]['score'] < bai_config['threshold'] or \
                not bai_mark.apply_bai_high_score(
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
        for ea in funcs:
            # refresh process status
            i += 1
            idaapi.replace_wait_box("Matching... ({}/{})".format(i, funcs_len))
            # check cancelled or not
            if idaapi.user_cancelled():
                stop()
                return
            status = None
            try:
                status = self._match_with_check(ea)
            finally:
                if status == 1:
                    succ += 1
                elif status == 0:
                    skip += 1
                else:
                    fail += 1
        stop()

    def upload(self, ea):
        try:
            func_id = self.mgr.upload(ea)
        except idaapi.DecompilationFailure as e:
            BinaryAILog.fail(idaapi.get_func_name(ea), str(e))
        except BinaryAIException as e:
            BinaryAILog.fatal(e)

        if func_id:
            BinaryAILog.success(idaapi.get_func_name(ea), func_id, "uploaded")

    def upload_funcs(self, funcs):

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
                func_id = self.mgr.upload(ea)
            except idaapi.DecompilationFailure as e:
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
                colors = [0xE8E4FF, 0xC0BAFF, 0x817FFF, 0x5E58FF]
                score = bai_mark.record[func.start_ea]['score']
                index = max(int((score*100-80)/5), 0)
                attrs.color = colors[index]

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
        # action = UIManager.ActionHandler("BinaryAI:UploadFunction", "Upload function", "", icon=97)
        # action.register_action(self.upload_callback, toolbar_name, menupath)
        action = UIManager.ActionHandler("BinaryAI:MatchAll", "Match all functions", "", icon=188)
        action.register_action(self.match_all_callback, toolbar_name, menupath)
        # action = UIManager.ActionHandler("BinaryAI:UploadAll", "Upload all functions", "", icon=88)
        # action.register_action(self.upload_all_callback, toolbar_name, menupath)

        apply_action = UIManager.ActionHandler("BinaryAI:Apply", "Apply")
        apply_action.register_action(self.apply_callback)

        match_action = UIManager.ActionHandler("BinaryAI:MatchSelected", "Match")
        # upload_action = UIManager.ActionHandler("BinaryAI:UploadSelected", "Upload")
        revert_action = UIManager.ActionHandler("BinaryAI:RevertSelected", "Revert")
        if match_action.register_action(self.selected_callback) and \
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


def check_ida():
    if idaapi.IDA_SDK_VERSION < 700:
        BinaryAILog.log(BinaryAILog.ERROR, "Need IDA >= 7.0")
        return False
    if not idaapi.init_hexrays_plugin():
        BinaryAILog.log(BinaryAILog.ERROR, "Hex-Rays decompiler does not exists")
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
        if check_ida():
            bai_mgr = BinaryAIManager()
            ui_mgr = UIManager(BinaryAIIDAPlugin.wanted_name, bai_mgr)
            if ui_mgr.register_actions():
                return idaapi.PLUGIN_KEEP
            else:
                BinaryAILog.log(BinaryAILog.ERROR, "Register actions failed")
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    BinaryAILog.level = BinaryAILog.DEBUG
    return BinaryAIIDAPlugin()
