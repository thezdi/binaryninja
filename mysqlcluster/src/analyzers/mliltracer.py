from binaryninja import *
from . import bnilvisitor
from . import config
from . import operations
from . import mlilfilter
from . import mliltaint
from . import mlilresults
from . import vardepends
from . import reachability
import logging

class MLILTracer(bnilvisitor.BNILVisitor, mlilfilter.MLILFilter, mliltaint.MLILTaint, mlilresults.MLILResults, vardepends.VarDepends, reachability.Reachability):

    def __init__(self, bv, func_addr):
        super(MLILTracer, self).__init__()
        
        self.funcargs = dict()
        self.source_vars = dict()  
        self.tainted_vars = dict()
        self.var_def_uses = dict()
        self.parent_var = 0

        self.taint_marker = config.taint_marker

        self.bv = bv
        self.function = self.bv.get_function_at(func_addr)
        self.function_mlilssa = [instr for instr in self.function.mlil.ssa_form.instructions]
        self.graph = self.get_function_graph(self.function)
        self.loops = self.get_function_loops(self.function)
        self.vargraph = 0

        typeinfo, demangled_name = demangle_gnu3(bv.arch, self.function.name)
        self.function_name = get_qualified_name(demangled_name)

        self.callee = dict()
        self.visited = list()
        self.results = list()

        config.stack.append(self.function_name)

    def __del__(self):
        
        config.stack.pop()

    def trace(self):
      
        # NOTE: Detect recursion using the stack trace
        if len(config.stack) != len(set(config.stack)):
            return

        if self.function.mlil.ssa_form is None:
            return

        for instr in self.function_mlilssa:
            self.visit(instr)

        self.filter_vars()
        
        if len(config.stack) >= config.max_depth:
            return

        self.trace_callee()

    def trace_callee(self):

        for expr, callee_vars in self.callee.items():

            if expr.dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                symbol = self.bv.get_symbol_at(expr.dest.constant)

                for func in config.function_hooks:
                    if symbol and func in symbol.name:
                        self.visit_function_hooks(expr, func, callee_vars)
                        break
                else:
                    dest = expr.dest.constant
                    args = self.get_args_to_pass(expr, callee_vars)

                    if not args:
                        continue

                    callee_trace = MLILTracer(self.bv, dest)

                    if callee_trace.function is None:
                        del callee_trace
                        continue
                    
                    callee_trace.set_function_args(args)
                    callee_trace.trace()
                    del callee_trace

