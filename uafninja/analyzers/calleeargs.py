from binaryninja import *
from . import config
import logging

class CalleeArgs():

    def get_function_args(self, function, funcargs):

        ssa_args = dict()

        for arg, value in funcargs.items():
            # BN function.parameter_vars is buggy #2463
            for var in function.vars:
                if var.name == arg:
                    ssa_var = SSAVariable(var, 0)
                    ssa_args[ssa_var] = value
                    break

        if not ssa_args and hasattr(function, "parameter_vars"):
            # Variable name does not seem to have "arg" prefix
            for arg_index, (arg, value) in enumerate(funcargs.items()):
                for param_index, var in enumerate(function.parameter_vars.vars):
                    if arg_index == param_index:
                        ssa_var = SSAVariable(var, 0)
                        ssa_args[ssa_var] = value
                        break

        return ssa_args

    def set_function_args(self, args):

        for arg, varinfo in args.items():
            if varinfo["vartype"] == config.GLOBAL:
                self.vars[arg] = varinfo
            else:
                argfunc = self.get_var_index(arg)
                self.vars[argfunc] = varinfo

    def get_args_to_pass(self, callee_function, expr):
        params = expr.params
        args = dict()

        if not params:
            return args

        arg_for_index = lambda x: "arg" + str(x + 1)

        for idx, param in enumerate(params):

            # Argument can be variable or a constant address.
            if param.operation is MediumLevelILOperation.MLIL_VAR_SSA:
                srcvar = param.src
            elif param.operation in [MediumLevelILOperation.MLIL_CONST_PTR, MediumLevelILOperation.MLIL_EXTERN_PTR]:
                srcvar = hex(param.constant)
            else: continue

            varinfo = self.getvar(srcvar)

            if varinfo is not None:
                args[arg_for_index(idx)] = varinfo

            # Handle cases where base of a structure is passed to the function, but write operation
            # happened to an element within the structure.
            elif param.value.type is RegisterValueType.StackFrameOffset:
                stackoffset = param.value.value
                for edge in self.data_graph.edges(hex(self.function.start), data=True):
                    src, dest, attr = edge

                    # Check for any memory writes above the offset under question (stack grows down).
                    # The offset values are in negative from the stack base.
                    if attr["write_offset"] >= stackoffset:
                        varinfo = dict(node = hex(self.function.start), offset = stackoffset, vartype = config.STACK)
                        args[arg_for_index(idx)] = varinfo
                        break

        if not args: return None
        
        ssa_args = self.get_function_args(callee_function, args)
        return ssa_args
