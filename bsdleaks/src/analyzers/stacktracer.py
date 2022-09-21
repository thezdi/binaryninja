from binaryninja import *

from . import config
from . import bnilvisitor
from . import helpers
from . import mliltracer
from . import dominators

class StackTracer(bnilvisitor.BNILVisitor):

    def __init__(self, bv, func_addr, dominators):
        super(StackTracer, self).__init__()

        self.bv = bv
        self.function = self.bv.get_function_at(func_addr)

        self.ssa_regs = dict()
        self.regs_visited = list()
        
        self.ssa_vars = dict()
        self.vars_visited = list()

        self.stores = dict()
        self.callee = list()

        # can be either dominators or post dominators
        self.dominators = dominators

    def trace(self):

        if None in (self.function.mlil.ssa_form, self.function.llil.ssa_form):
            return

        # Perform both MLIL and LLIL analysis
        for instr in self.function.mlil.ssa_form.instructions:
            self.visit(instr)
        
        for instr in self.function.llil.ssa_form.instructions:
            self.visit(instr)

        self.trace_callee()

    def log_stores(self, dest, size):

        if (dest not in self.stores) or (self.stores[dest] < size):
            self.stores[dest] = size

    def get_value_for_regtype(self, value):

        if isinstance(value, int):
            return value

        if value.type == RegisterValueType.StackFrameOffset:
            return value.offset

        elif value.type == RegisterValueType.ConstantValue:
            return value.value

    def visit_ssa_reg_uses(self, expr):
        
        dest_refs = expr.function.get_ssa_reg_uses(expr.dest)
        for ref in dest_refs:
            self.visit(ref)

    def filter_ssa_value(self, ssa, ssa_value, ssa_value_store):

        if (ssa_value.type == RegisterValueType.ConstantValue and ssa_value.value != 0):
            return ssa_value

        elif ssa_value.type == RegisterValueType.StackFrameOffset:
            return ssa_value

        elif (ssa_value.type == RegisterValueType.UndeterminedValue and ssa in ssa_value_store):
            value = ssa_value_store[ssa]
            if value != 0: 
                return value

        else: return None

    def visit_LLIL_REG_PHI(self, expr):
        
        if expr in self.regs_visited:
            return

        # NOTE: Add rules to PHI function depending on the codebase. In this case, the value can be
        # stack offset or a constant value or an integer representing a heap address. We choose any
        # of these SSA values which are not 0 i.e. NULL pointer initialization or 0 constant.
        for ssa_reg in expr.src:
        
            ssa_reg_value = expr.function.get_ssa_reg_value(ssa_reg)
        
            value = self.filter_ssa_value(ssa_reg, ssa_reg_value, self.ssa_regs)

            if not value:
                continue

            self.ssa_regs[expr.dest] = value  
            self.regs_visited.append(expr)
            self.visit_ssa_reg_uses(expr)
            break
            
    def visit_LLIL_REG_SSA(self, expr):
        ssa_reg = expr.src

        if ssa_reg in self.ssa_regs:
            rval = self.ssa_regs[ssa_reg]
            return self.get_value_for_regtype(rval)
       
    def visit_LLIL_SET_REG_SSA(self, expr):
        
        if expr in self.regs_visited:
            return

        dest = expr.dest
        src = self.visit(expr.src)

        if src is not None:
            self.ssa_regs[dest] = src
            self.regs_visited.append(expr)
            self.visit_ssa_reg_uses(expr)

    def visit_LLIL_STORE_SSA(self, expr):
       
        if not dominators.is_dominator(self.function, self.dominators, expr):
            return

        if expr.dest.value.type == RegisterValueType.StackFrameOffset:
            self.log_stores(expr.dest.value.offset, expr.size)

        elif expr.dest.value.type == RegisterValueType.UndeterminedValue:
            dest = self.visit(expr.dest)

            if dest is not None:
                self.log_stores(dest, expr.size)

    def visit_LLIL_ADD(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if None not in (left, right):
            return (left + right)

    def visit_LLIL_CONST(self, expr):
        return expr.constant
    
    def get_ssa_value_for_reg(self, expr, register):
        
        var = expr.get_var_for_reg(register)
        version = expr.get_ssa_var_version(var)
        ssa_var = SSAVariable(var, version)

        if ssa_var in self.ssa_vars:
            ssa_val = self.ssa_vars[ssa_var]
            return self.get_value_for_regtype(ssa_val)

    def get_value_for_reg(self, expr, register):
        
        rval = expr.get_possible_reg_values(register)
        value = self.get_value_for_regtype(rval)

        if value is None:
            value = self.get_ssa_value_for_reg(expr.mlil.ssa_form, register)

        return value

    def get_reps_opsize(self, expr):

        llils = self.function.get_llils_at(expr.address)

        for llil in llils:
            if llil.operation == LowLevelILOperation.LLIL_STORE:
                return llil.size

    def visit_LLIL_GOTO(self, expr):

        # MLIL_GOTO as a hook for x86 reps emulation
        if self.bv.get_disassembly(expr.address).startswith("rep"):
        
            if not dominators.is_dominator(self.function, self.dominators, expr):
                return

            opsize = self.get_reps_opsize(expr)
            
            rdi = self.get_value_for_reg(expr, "rdi") 
            rcx = self.get_value_for_reg(expr, "rcx")

            if None not in (rdi, rcx, opsize):
                self.log_stores(rdi, rcx * opsize)
 
    def visit_LLIL_CALL_SSA(self, expr):

        if expr not in self.callee:
            self.callee.append(expr)
    
    def visit_LLIL_TAILCALL_SSA(self, expr):
        self.visit_LLIL_CALL_SSA(expr)

    def get_value_for_arg(self, expr, arg):
        
        params = expr.mlil.ssa_form.params
        argno = lambda _arg: int(_arg.split("arg").pop())

        if argno(arg) < len(params):
            param_expr = params[argno(arg)]
       
            argval = self.get_value_for_regtype(param_expr.value)
        
            if argval is None:
                return self.visit(param_expr)
            else:
                return argval
        else:
            return None

    def visit_function_hooks(self, expr, func):

        args = config.function_hooks[func]
        
        if not args:
            return

        dest, size = args
        dest = self.get_value_for_arg(expr, dest)
        size = self.get_value_for_arg(expr, size)
        
        if None not in (dest, size):
            self.log_stores(dest, size)

    def get_args_to_pass(self, expr):

        params = expr.mlil.ssa_form.params 
        args = dict()

        if not params: 
            return args

        arg_for_index = lambda x: "arg" + str(x + 1)

        for idx, param in enumerate(params):

            if param.value.type == RegisterValueType.StackFrameOffset:
                args[arg_for_index(idx)] = param.value.offset

            elif param.value.type == RegisterValueType.UndeterminedValue: 
                value = self.visit(param)

                if value is not None:
                    args[arg_for_index(idx)] = value

        return args

    def trace_callee(self):

        for expr in self.callee:
        
            if not dominators.is_dominator(self.function, self.dominators, expr):
                continue
            
            if expr.dest.operation == LowLevelILOperation.LLIL_CONST_PTR:
                symbol = self.bv.get_symbol_at(expr.dest.constant)
                
                for func in config.function_hooks:
                    if symbol and func in symbol.name:
                        self.visit_function_hooks(expr, func)
                        break
                else:
                    dest = expr.dest.constant
                    args = self.get_args_to_pass(expr)
                    
                    if not args: 
                        continue
                  
                    callee_function = self.bv.get_function_at(dest)
                    post_dominators = dominators.get_mlilfunc_post_dominators(callee_function)
                    callee_trace = mliltracer.MLILTracer(self.bv, dest, post_dominators, self.stores)

                    if callee_trace.function is None:
                        del callee_trace
                        continue
                        
                    callee_trace.set_function_args(args)
                    callee_trace.trace()
                    del callee_trace
                        
            elif expr.dest.operation == LowLevelILOperation.LLIL_LOAD:
                pass

    def check_info_leak(self, dest, size):
        
        return helpers.get_leaked_bytes(self.stores, dest, size)

    def visit_ssa_vars_uses(self, expr):
        
        dest_refs = expr.function.get_ssa_var_uses(expr.dest)

        for ref in dest_refs:
            self.visit(ref)
    
    def visit_MLIL_VAR_PHI(self, expr):

        if expr in self.vars_visited:
            return

        for ssa_var in expr.src:

            ssa_var_value = expr.function.get_ssa_var_value(ssa_var)
            value = self.filter_ssa_value(ssa_var, ssa_var_value, self.ssa_vars)

            if not value:
                continue

            self.ssa_vars[expr.dest] = value
            self.vars_visited.append(expr)
            self.visit_ssa_vars_uses(expr)
            break

    def visit_MLIL_ADDRESS_OF(self, expr):
        return expr.value

    def visit_MLIL_VAR_SSA(self, expr):
        ssa_var = expr.src

        if ssa_var in self.ssa_vars:
            vval = self.ssa_vars[ssa_var]
            return self.get_value_for_regtype(vval)

    def visit_MLIL_VAR_SSA_FIELD(self, expr):
        return self.visit_MLIL_VAR_SSA(expr)

    def visit_MLIL_SET_VAR_SSA(self, expr):
        
        if expr in self.vars_visited:
            return

        dest = expr.dest
        src = self.visit(expr.src)

        if src is None:
            return

        self.ssa_vars[dest] = src
        self.vars_visited.append(expr)

        dest_refs = expr.function.get_ssa_var_uses(dest)
        for ref in dest_refs:
            self.visit(ref)
