import gc
import argparse
import logging
from binaryninja import *

import analyzers.config
from analyzers.mliltracer import *
from analyzers.stacktracer import *
from analyzers.searchvar import *
from analyzers.helpers import *
from analyzers.dominators import *

parser = argparse.ArgumentParser()
parser.add_argument("filename", help = "path to binary ninja bndb file")
parser.add_argument("--loglevel", help = "choose logging level for debugging", default = "INFO")
parser.add_argument("--logname", help = "choose log file name", default = "analysis.log")
parser.add_argument("--function_hooks", help = "provide path to json config")
parser.add_argument("--allocator_funcs", help = "provide path to json config")
parser.add_argument("--dominators", help = "enable dominator based checks", dest = "dominators", action = "store_true")
parser.set_defaults(dominators = False)
args = parser.parse_args()

bv = binaryview.BinaryViewType.get_view_of_file(args.filename)

numeric_level = getattr(logging, args.loglevel.upper(), None)
logger = logging.getLogger()
logger.setLevel(numeric_level)

filehandler = logging.FileHandler(args.logname)
filehandler.setLevel(numeric_level)
logger.addHandler(filehandler)

consolehandler = logging.StreamHandler(sys.stdout)
consolehandler.setLevel(numeric_level)
logger.addHandler(consolehandler)

if args.function_hooks is not None:
    with open(args.function_hooks) as func_hooks:
        config.function_hooks = json.load(func_hooks)

if args.allocator_funcs is not None:
    with open(args.allocator_funcs) as alloc_funcs:
        config.allocator_funcs = json.load(alloc_funcs)

config.check_dominators = args.dominators

logging.info("Starting analysis...")

def analyze_function(bv, name, var_memory, var_size):

    function_sym = bv.get_symbol_by_raw_name(name)

    if function_sym is None:
        return
    
    for ref in bv.get_code_refs(function_sym.address):
        function = ref.function

        llil = function.get_low_level_il_at(ref.address).ssa_form

        if llil.operation != LowLevelILOperation.LLIL_CALL_SSA:
            continue

        mlil = llil.mlil.ssa_form

        source = get_var_for_arg(mlil, var_memory)
        size = get_var_for_arg(mlil, var_size)

        if (source.value.type == RegisterValueType.StackFrameOffset and  
            size.value.type == RegisterValueType.ConstantValue):
                   
            dominators = get_llil_dominators(function, llil)
            tracer = StackTracer(bv, function.start, dominators)
            tracer.trace()
            leaked_offsets = tracer.check_info_leak(source.value.offset, size.constant)
            
            del tracer
           
            log_leak_info(leaked_offsets, size.constant, ref.address, function.name)

analyze_function(bv, "copyout", "arg0", "arg2")
