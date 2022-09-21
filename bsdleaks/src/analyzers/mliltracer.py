from binaryninja import *
from . import bnilvisitor
from . import config
from . import helpers
from . import dominators

class MLILTracer(bnilvisitor.BNILVisitor):

    def __init__(self, bv, func_addr, dominators, stores):
        super(MLILTracer, self).__init__()

        self.ssa_vars = dict()

        self.bv = bv
        self.function = self.bv.get_function_at(func_addr)
        self.instructions = [x for x in self.function.mlil.ssa_form.instructions]
        self.stores = stores

        self.callee = list()
        self.visited = list()

        # can be either dominators or post dominators
        self.dominators = dominators

        config.stack.append(self.function.name)

    def __del__(self):

        config.stack.pop()

    def set_function_args(self, funcargs):
   
        for arg, value in funcargs.items():
            # BN function.parameter_vars is buggy #2463
            for var in self.function.vars:
                if var.name == arg:
                    ssa_var = SSAVariable(var, 0)
                    self.ssa_vars[ssa_var] = value
                    break

    def set_function_vars(self, funcvars):

        for ssa_var, value in funcvars.items():
            self.ssa_vars[ssa_var] = value

    def trace(self):

        # NOTE: Detect recursion using the stack trace
        if len(config.stack) != len(set(config.stack)):
            return

        if self.function.mlil.ssa_form is None:
            return

        for instr in self.function.mlil.ssa_form.instructions:
            self.visit(instr)
      
        if len(config.stack) >= config.max_depth:
            return

        self.trace_callee()

    def log_stores(self, dest, size):

        if (dest not in self.stores) or (self.stores[dest] < size): 
            self.stores[dest] = size

    def visit_MLIL_SET_VAR_SSA(self, expr):

        if expr in self.visited: 
            return

        dest = expr.dest
        src = self.visit(expr.src)

        if src is not None:
            self.ssa_vars[dest] = src
            self.visited.append(expr)

            dest_refs = expr.function.get_ssa_var_uses(dest)
            for ref in dest_refs:
                self.visit(ref)

    def visit_MLIL_VAR_SSA(self, expr):
        ssa_var = expr.src
    
        if ssa_var in self.ssa_vars:
            return self.ssa_vars[ssa_var]

    def visit_MLIL_VAR_SSA_FIELD(self, expr):
        return self.visit_MLIL_VAR_SSA(expr)

    def visit_MLIL_VAR_PHI(self, expr):
        ssa_var_values = list()

        if expr in self.visited:
            return

        # NOTE: Add rules to PHI function depending on the codebase. In this case, we choose
        # the destination value as the only resolved value or if all source values are same.
        for ssa_var in expr.src:
            if ssa_var in self.ssa_vars:
                ssa_var_values.append(self.ssa_vars[ssa_var])

        if not ssa_var_values:
            return

        source_value = ssa_var_values.pop(0)

        if all(value == source_value for value in ssa_var_values):
            self.ssa_vars[expr.dest] = source_value
            self.visited.append(expr)

    def visit_MLIL_STORE_SSA(self, expr):

        if not dominators.is_dominator(self.function, self.dominators, expr):
            return

        dest = self.visit(expr.dest)
        size = expr.size
       
        if dest is not None:
            self.log_stores(dest, size)

    def visit_MLIL_ADD(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)
        
        if None not in (left, right):
            return (left + right)

    def visit_MLIL_CONST(self, expr):
        return expr.constant
    
    def visit_MLIL_SUB(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if None not in (left, right):
            return (left - right)

    def visit_MLIL_ZX(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_LSR(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if None not in (left, right) and right > 0:
            return (left >> right)

    def visit_MLIL_AND(self, expr):
        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if None not in (left, right):
            return (left & right)
    
    def get_ssa_value_for_reg(self, expr, register):

        var = expr.get_var_for_reg(register)
        version = expr.get_ssa_var_version(var)
        ssa_var = SSAVariable(var, version)

        if ssa_var in self.ssa_vars:
            return self.ssa_vars[ssa_var]

    def get_reps_opsize(self, expr):

        llils = self.function.get_llils_at(expr.address)

        for llil in llils:
            if llil.operation == LowLevelILOperation.LLIL_STORE:
                return llil.size

    def resolve_optimization(self, expr):

        pointer_value, size_value = None, None

        bb = dominators.get_mlil_basic_block(self.function, expr)

        for blks in bb.dominators:

            for index in range(blks.start, blks.end):
                instr = self.instructions[index]

                if instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:

                    # VAR = VAR & BYTESIZE
                    if (instr.src.operation == MediumLevelILOperation.MLIL_AND
                        and instr.src.right.operation == MediumLevelILOperation.MLIL_CONST
                        and instr.src.right.constant == 1):

                        var = instr.src.left.vars_read[0]
                        if var in self.ssa_vars:
                            pointer_value = self.ssa_vars[var]

                    # VAR = zx.q(VAR u>> 3)
                    if (instr.src.operation == MediumLevelILOperation.MLIL_ZX
                        and instr.src.src.operation == MediumLevelILOperation.MLIL_LSR
                        and instr.src.src.right.operation == MediumLevelILOperation.MLIL_CONST
                        and instr.src.src.right.constant == 3):

                        if hasattr(instr.src.src.left.possible_values, "values"):
                            size_value = max(instr.src.src.left.possible_values.values)

                # IF (VAR & BYTESIZE) != 0
                elif instr.operation == MediumLevelILOperation.MLIL_IF:
                    if (hasattr(instr.condition, "left")
                        and instr.condition.left.operation == MediumLevelILOperation.MLIL_AND
                        and instr.condition.left.right.operation == MediumLevelILOperation.MLIL_CONST
                        and instr.condition.left.right.constant == 1):

                        var = instr.condition.left.vars_read[0]
                        if var in self.ssa_vars:
                            pointer_value = self.ssa_vars[var]

        return pointer_value, size_value

    def visit_MLIL_GOTO(self, expr):

        if expr in self.visited:
            return

        # MLIL_GOTO as a hook for x86 reps emulation
        if self.bv.get_disassembly(expr.address).startswith("rep"):
            
            if not dominators.is_dominator(self.function, self.dominators, expr):
                return
            
            opsize = self.get_reps_opsize(expr)
            rdi = self.get_ssa_value_for_reg(expr, "rdi")
            rcx = self.get_ssa_value_for_reg(expr, "rcx")
            
            if None not in (rdi, rcx, opsize):
                self.log_stores(rdi, rcx * opsize)
                self.visited.append(expr)

            else:
                # Handle pointer alignment code generated by compilers
                rdi, rcx = self.resolve_optimization(expr)

                if None not in (rdi, rcx):
                    self.log_stores(rdi, rcx)
                    self.visited.append(expr)

    def visit_MLIL_CALL_SSA(self, expr):
        
        if expr not in self.callee:
            self.callee.append(expr)

    def visit_MLIL_TAILCALL_SSA(self, expr):
        self.visit_MLIL_CALL_SSA(expr)

    def get_value_for_arg(self, expr, arg):

        params = expr.params
        argno = lambda _arg: int(_arg.split("arg").pop())
        
        if argno(arg) < len(params):
            param_expr = params[argno(arg)]
            return self.visit(param_expr)
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
        params = expr.params
        args = dict()

        if not params:
            return args

        arg_for_index = lambda x: "arg" + str(x + 1)

        for idx, param in enumerate(params):
            value = self.visit(param)

            if value is not None:
                args[arg_for_index(idx)] = value

        return args

    def trace_callee(self):

        for expr in self.callee:

            if not dominators.is_dominator(self.function, self.dominators, expr):
                continue

            if expr.dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
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
                    callee_trace = MLILTracer(self.bv, dest, post_dominators, self.stores)
                    
                    if callee_trace.function is None:
                        del callee_trace
                        continue

                    callee_trace.set_function_args(args)
                    callee_trace.trace()
                    del callee_trace

            elif expr.dest.operation == MediumLevelILOperation.MLIL_LOAD:
                pass

    def check_info_leak(self, dest, size):
        return helpers.get_leaked_bytes(self.stores, dest, size)
