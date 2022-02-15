from binaryninja import *
from . import operations
from . import config
import logging

class MLILResults():

    def get_stack_trace(self):
        
        stack_trace  = "[PATH]"
        stack_trace += "".join(["->" + func for func in config.stack])
        return stack_trace

    def check_results(self, expr, ssa_var):

        for fields in MediumLevelILInstruction.ILOperations[expr.operation]:
            x, y = fields
            if y == "expr":
                self.check_results(getattr(expr, x), ssa_var)
       
        if expr in self.results:
            return

        instr = self.function_mlilssa[expr.instr_index]

        if expr.operation == MediumLevelILOperation.MLIL_STORE_SSA and ssa_var in expr.dest.vars_read:
            logging.info("Potential OOB write @ 0x%lx %s %s", expr.address, instr, self.get_stack_trace())
            self.results.append(expr)
            config.vuln = True
        
        elif expr.operation == MediumLevelILOperation.MLIL_LOAD_SSA and ssa_var in expr.vars_read and instr.operation not in operations.MLIL_CALLS:
            logging.info("Potential OOB read @ 0x%lx %s %s", expr.address, instr, self.get_stack_trace())
            self.results.append(expr)
            config.vuln = True
        
        elif expr.operation == MediumLevelILOperation.MLIL_IF and self.check_loop_operation(expr):
            if self.check_x86_reps(expr):
                asm = self.bv.get_disassembly(expr.address)
                logging.info("Potential controlled size in x86 reps @ 0x%lx %s [%s]", expr.address, asm, self.get_stack_trace())
            else:
                instr, hlil_address = self.loops[expr.address]
                logging.info("Potential controlled condition in loop @ 0x%lx %s %s", hlil_address, instr, self.get_stack_trace()) 

            self.results.append(expr)
            config.vuln = True

        elif expr.operation in operations.MLIL_CALLS:
            if expr.dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                if expr in self.callee:
                    self.callee[expr].append(ssa_var)
                else:
                    self.callee[expr] = [ssa_var]
            elif expr.dest.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
                if ssa_var in expr.dest.vars_read:
                    logging.info("Potential controlled indirect call @ 0x%lx %s %s", expr.address, instr, self.get_stack_trace())
                    self.results.append(expr)
                    config.vuln = True

    def log_untrusted_ptr(self, expr, dest):

        # Log tainted pointer loads if the destination var type confidence is MAX(255).
        if (dest.var.type.type_class == TypeClass.PointerTypeClass
            and dest.var.type.confidence == 255 and expr.src.operation == MediumLevelILOperation.MLIL_LOAD_SSA):
        
            instr = self.function_mlilssa[expr.instr_index]
            logging.info("Potential untrusted pointer load @ 0x%lx %s %s", expr.address, instr, self.get_stack_trace())
            config.vuln = True

    def get_var_for_arg(self, expr, arg):

        params = expr.params
        argno = lambda _arg: int(_arg.split("arg").pop())

        if argno(arg) < len(params):
            param = params[argno(arg)]
            if param.operation in operations.MLIL_GET_VARS:
                return param.vars_read[0]

    def visit_function_hooks(self, expr, func, tainted_vars):

        args = config.function_hooks[func]
        if not args:
            return

        for arg in args:
            ssa_var = self.get_var_for_arg(expr, arg)
            if ssa_var in tainted_vars:
                logging.info("Potential controlled args in call to %s @ 0x%lx %s %s", func, expr.address, expr, self.get_stack_trace())
                config.vuln = True
                break

    def get_args_to_pass(self, expr, tainted_vars):
        params = expr.params
        args = dict()

        if not params:
            return args

        arg_for_index = lambda x: "arg" + str(x + 1)

        for idx, param in enumerate(params):
            if param.operation in operations.MLIL_GET_VARS:
                param_var = param.vars_read[0]
                if param_var in tainted_vars:
                    args[arg_for_index(idx)] = self.tainted_vars[param_var]

        return args
