from .error import BinaryAIException
try:
    import idaapi
    import idautils
except ImportError:
    raise BinaryAIException("SDK_ERROR", "Failed to import idaapi or idautils", None, None)

import ctypes
import hashlib
import json


M_MAX = 0x49  # first unused opcode
All_STR = dict(map(lambda i: (i.ea, str(i)), idautils.Strings()))


class Graph:
    def __init__(self):
        self.graph = {"directed": True, "graph": {}, "nodes": [], "links": [], "multigraph": False}
        self.nodes_num = 0
        self.edges_num = 0

    def add_node(self, serial, feat):
        self.graph["nodes"].append({"id": serial, "feat": feat})
        self.nodes_num += 1

    def add_edge(self, serial, succ):
        self.graph["links"].append({"source": serial, "target": succ})
        self.edges_num += 1

    def remove_featempty_nodes(self):
        remove_nodes = []
        for node in self.graph["nodes"]:
            if not node["feat"]:
                self.remove_edge_by_node(node["id"])
                remove_nodes.append(node)
        for node in remove_nodes:
            self.graph["nodes"].remove(node)
            self.nodes_num -= 1

    def remove_edge_by_node(self, id):
        remove_edges = []
        for edge in self.graph["links"]:
            if edge["source"] == id or edge["target"] == id:
                remove_edges.append(edge)
        for edge in remove_edges:
            self.graph["links"].remove(edge)
            self.edges_num -= 1

    def have_nodes(self):
        return self.nodes_num > 0

    def have_edges(self):
        return self.edges_num > 0


def get_idb_info():
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = '64'
    elif info.is_32bit():
        bits = '32'
    else:
        assert(False)

    return ''.join([info.procName, bits])


class CtreeFeature(idaapi.ctree_visitor_t):
    def __init__(self, state, expr, num, stri):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.state = state
        self.expr = expr
        self.num = num
        self.stri = stri

    def visit_expr(self, item):
        self.expr.append(item.op)
        if item.op == idaapi.cot_num:
            self.num.append(ctypes.c_long(item.n._value).value)
        elif item.op == idaapi.cot_obj:
            addr = item.obj_ea
            if addr in All_STR:
                s = All_STR[addr]
                if s is not None:
                    self.stri.append(s)
        elif item.op == idaapi.cot_str:
            self.stri.append(item.string)

        return 0

    def visit_insn(self, item):
        self.state.append(item.op)
        return 0


def parse_minsn(minsn, micro_int, ins=None):
    ins = [] if ins is None else ins
    ins.append(minsn.opcode)
    for op in [minsn.l, minsn.r, minsn.d]:
        if op.t == idaapi.mop_d:
            parse_minsn(op.d, micro_int, ins)
        elif op.t == idaapi.mop_f:
            for arg in op.f.args:
                if arg.t == idaapi.mop_d:
                    parse_minsn(arg.d, micro_int, ins)
                else:
                    ins.append(arg.t + M_MAX)
        else:
            ins.append(op.t + M_MAX)
            if op.t == idaapi.mop_n:
                micro_int.append(ctypes.c_long(op.nnn.value).value)
    return ins


def parse_func(pfn):
    try:
        hf = idaapi.hexrays_failure_t()
        cfunc = idaapi.decompile(pfn.start_ea, hf)
        mbr = idaapi.mba_ranges_t(pfn)
        mba = idaapi.gen_microcode(
            mbr,
            hf,
            None,
            idaapi.DECOMP_NO_WAIT | idaapi.DECOMP_NO_CACHE,
            idaapi.MMAT_GLBOPT3
        )
    except Exception:
        return
    if mba is None:
        return

    G = Graph()
    ctree_state, ctree_expr, ctree_int, ctree_str, micro_int = [], [], [], [], []

    # node level
    for i in range(mba.qty):
        mb = mba.get_mblock(i)
        minsn = mb.head
        blk = []
        while minsn:
            ins = parse_minsn(minsn, micro_int)
            blk.append(ins)
            minsn = minsn.next

        G.add_node(mb.serial, feat=blk)
        for succ in mb.succset:
            G.add_edge(mb.serial, succ)
    G.remove_featempty_nodes()

    if not G.have_nodes():
        return

    # add a fake edge if there is no edge
    if not G.have_edges():
        G.add_edge(G.graph['nodes'][0]['id'], G.graph['nodes'][0]['id'])

    # graph level
    ctree_fea = CtreeFeature(ctree_state, ctree_expr, ctree_int, ctree_str)
    ctree_fea.apply_to(cfunc.body, None)

    G.graph['graph']['c_state'], G.graph['graph']['c_expr'], G.graph['graph']['c_int'], G.graph['graph'][
        'c_str'], G.graph['graph']['m_int'] = ctree_state, ctree_expr, ctree_int, ctree_str, micro_int
    G.graph['graph']['arg_num'] = len(cfunc.argidx)

    func_bytes = b''
    for start, end in idautils.Chunks(pfn.start_ea):
        fb = idaapi.get_bytes(start, end-start)
        func_bytes += fb
    G.graph['graph']['hash'] = hashlib.md5(func_bytes).hexdigest()

    return G.graph


def get_func_feature(ea):
    """
    get function feature by IDA Pro

    Args:
        ea(ea_t): function address

    Returns:
        func_feat(string): function feature
    """
    pfn = idaapi.get_func(ea)
    G = parse_func(pfn)
    if G:
        func_feat = json.dumps(G)
        return func_feat
    return None
