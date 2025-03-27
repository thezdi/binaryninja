import argparse
import logging
from binaryninja import *

import analyzers.config as config

from analyzers.mliltracer import *
from analyzers.tracergraph import *
from analyzers.logcolors import *

import networkx as nx
import sys

def alloctracer(bv, ref, tracking_vars):
    # Wrapper around MLILTracer. 
    ref_mlil = ref.function.get_low_level_il_at(ref.address).mlil.ssa_form
    return MLILTracer(bv, ref.function, vars_to_track = tracking_vars, allocexpr = ref_mlil)

def generate_data_graph(data_graph, ref):
    D = nx.drawing.nx_pydot.to_pydot(data_graph)
    for edge in D.get_edges():
        attributes = edge.get_attributes()
        edge.set_label("write: %s, points: %s" % 
                (attributes["write_offset"], attributes["points_offset"]))

    filename = "Data_%s.svg" % (hex(ref.address))
    D.write_svg(filename)

def analyze_function(bv, func_address):

    for ref in bv.get_code_refs(func_address):
        if ref is None: continue

        if args.filter_function and ref.function.name != args.filter_function:
            continue

        ref_mlil = ref.function.get_low_level_il_at(ref.address).mlil
        if ref_mlil is None: continue

        ref_mlil_ssa = ref_mlil.ssa_form
        if ref_mlil.ssa_form is None: continue

        # In case the allocator returns the pointer through an argument, 
        # add that to tracking vars.
        destvar = ref_mlil_ssa.vars_written[0]
        tracking_vars = list()
        tracking_vars.append(destvar)

        tracer = alloctracer(bv, ref, tracking_vars)
        logging.warning("Building data graph for reference @ 0x%x" % (ref.address))
        tracer.trace_allocator()

        tracer.detect_uaf(tracer.control_graph, tracer.log_blks, ref_mlil_ssa)

        # Dump data or control graph for debugging.
        if args.dump_data_graph:
            generate_data_graph(tracer.data_graph, ref)
       
        del tracer

def get_imported_func_sym(function_syms):
    for sym in function_syms:
        if sym.type in [SymbolType.ImportedFunctionSymbol, SymbolType.FunctionSymbol]:
            return sym

def find_deallocators(all_dealloc_funcs):
    for func in all_dealloc_funcs:
        function_syms = bv.get_symbols_by_name(func)
        sym = get_imported_func_sym(function_syms)

        if sym is None: continue

        for ref in bv.get_code_refs(sym.address):
            ref_mlil = ref.function.get_low_level_il_at(ref.address).mlil
            if ref_mlil is None: continue

            ref_mlil_ssa = ref_mlil.ssa_form
            if ref_mlil.ssa_form is None: continue

            for param in ref_mlil_ssa.params:
                if param.value.type == RegisterValueType.EntryValue:
                    logging.critical("Potential deallocator wrapper function %s @ 0x%x"
                            % (ref.function.name, ref.function.start))

parser = argparse.ArgumentParser()
parser.add_argument("filename", help = "path to binary ninja bndb file")
parser.add_argument("--loglevel", help = "choose logging level for debugging", default = "INFO")
parser.add_argument("--logname", help = "choose log file name", default = "analysis.log")
parser.add_argument("--propagate_reads", help = "propagate reads from allocated memory", action = "store_true")
parser.add_argument("--check_type_size", help = "propagate pointers by checking SSA variable type", action = "store_true")
parser.add_argument("--function_hooks", help = "provide path to json config")
parser.add_argument("--allocator_funcs", help = "provide path to json config", required=True)
parser.add_argument("--dump_data_graph", help = "enable dumping data graph for debugging", action = "store_true")
parser.add_argument("--dominators", help = "enable dominator based checks", dest = "dominators", action = "store_true")
parser.add_argument("--filter_function", help = "provide a specific function name to track")
parser.add_argument("--find_deallocators", help = "enumerate possible wrappers for deallocators", action = "store_true")
parser.add_argument("--recursion_limit", help = "increase recursion limit when needed", type=int, nargs="?", 
                                                                        const = sys.getrecursionlimit()*2, default = None)
parser.set_defaults(dominators = False)
args = parser.parse_args()

bv = load(args.filename)
config.propagate_reads = args.propagate_reads
config.check_type_size = args.check_type_size
config.dominators = args.dominators

numeric_level = getattr(logging, args.loglevel.upper(), None)
logger = logging.getLogger()
logger.setLevel(numeric_level)

filehandler = logging.FileHandler(args.logname)
filehandler.setLevel(numeric_level)
logger.addHandler(filehandler)

consolehandler = logging.StreamHandler(sys.stdout)
consolehandler.setLevel(numeric_level)
consolehandler.setFormatter(CustomFormatter())
logger.addHandler(consolehandler)

if args.recursion_limit:
    sys.setrecursionlimit(args.recursion_limit)

if args.function_hooks is not None:
    with open(args.function_hooks) as func_hooks:
        config.function_hooks = json.load(func_hooks)

if args.allocator_funcs is not None:
    with open(args.allocator_funcs) as alloc_funcs:
        config.allocator_funcs = json.load(alloc_funcs)

config.check_dominators = args.dominators

logging.info("Starting analysis using %s", args.allocator_funcs)

for allocators in config.allocator_funcs["allocators"]:
    dealloc_funcs = allocators["dealloc"]["func"]
    for func in dealloc_funcs:
        if func not in config.all_dealloc_funcs:
            config.all_dealloc_funcs.append(func)
        
if args.find_deallocators:
    find_deallocators(config.all_dealloc_funcs)

for allocators in config.allocator_funcs["allocators"]:
    alloc_func = allocators["alloc"]["func"]
    dealloc_func = allocators["dealloc"]["func"]
    function_syms = bv.get_symbols_by_name(alloc_func)
    config.dealloc_func = dealloc_func
    config.alloc_func = alloc_func
    
    if len(function_syms) == 0:
        continue

    for function_sym in function_syms:
        analyze_function(bv, function_sym.address)
