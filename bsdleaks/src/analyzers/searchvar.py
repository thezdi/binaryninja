from binaryninja import *
from . import bnilvisitor
from . import config

class SearchVar(bnilvisitor.BNILVisitor):

    def __init__(self, bv, func_addr, ssa_var):
        super(SearchVar, self).__init__()

        self.bv = bv
        self.function = self.bv.get_function_at(func_addr)

        self.current_var = ssa_var
        self.target_var = dict()

        self.visited_defs = list()

    def search_var_initialization(self):
       
        vardef = self.get_ssa_var_defs(self.current_var)
        
        if vardef is not None:
            self.visit(vardef)
    
    def get_ssa_var_defs(self, var):
        
        return self.function.mlil.ssa_form.get_ssa_var_definition(var)

    def get_value_for_arg(self, expr, arg):

        params = expr.params
        argno = lambda _arg: int(_arg.split("arg").pop())

        if argno(arg) < len(params):
            param_expr = params[argno(arg)]
            return self.visit(param_expr)
        else:
            return None

    def visit_allocator_hooks(self, expr, func):

        args = config.allocator_funcs[func]

        if not args:
            return

        size = self.get_value_for_arg(expr, args[0])

        if isinstance(size, int):
            return size

    def visit_MLIL_CALL_SSA(self, expr):

        func_address = self.visit(expr.dest)

        if not isinstance(func_address, int):
            return
    
        func_sym = self.bv.get_function_at(func_address).name
        
        if func_sym in config.allocator_funcs:
       
            alloc_size = self.visit_allocator_hooks(expr, func_sym)

            if alloc_size is not None:
                self.target_var[self.current_var] = -alloc_size
            else:
                # NOTE: Assign an arbitrary starting address
                self.target_var[self.current_var] = -0x10000

    def visit_MLIL_ADDRESS_OF(self, expr):
        
        self.target_var[self.current_var] = expr.value

    def visit_MLIL_SET_VAR_SSA(self, expr):
        
        if expr in self.visited_defs:
            return

        self.current_var = self.visit(expr.src)
        
        if isinstance(self.current_var, SSAVariable):
            vardef = self.get_ssa_var_defs(self.current_var)
            self.visited_defs.append(expr)
            self.visit(vardef)

    def visit_MLIL_VAR_PHI(self, expr):

        if expr in self.visited_defs:
            return

        for ssa_var in expr.src:
            self.current_var = ssa_var
            vardef = self.get_ssa_var_defs(ssa_var)
            self.visited_defs.append(expr)
            self.visit(vardef)

    def visit_MLIL_CONST_PTR(self, expr):
        return expr.constant
    
    def visit_MLIL_CONST(self, expr):
        self.target_var[self.current_var] = expr.value
        return expr.constant

    def visit_MLIL_VAR_SSA(self, expr):
        return expr.src

