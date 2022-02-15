from binaryninja import *
from . import bnilvisitor
from . import config
from . import configsrcfunc
from . import operations
from . import mlilfilter
import logging

class MLILTaint():

    def set_function_args(self, funcargs):

        for arg, value in funcargs.items():
            # BN function.parameter_vars is buggy #2463
            for var in self.function.vars:

                if var.name == arg:
                    ssa_var = SSAVariable(var, 0)

                    if self.is_pointer(value):
                        self.source_vars[ssa_var] = value

                    elif self.is_tainted(value):
                        self.tainted_vars[ssa_var] = value

                        # NOTE: For argument vars, use first basic block as definition
                        definition = self.function.mlil.ssa_form[0]
                        self.get_var_statements(definition, ssa_var, True)
                    
                    break

    def set_function_vars(self, funcvars):
        for ssa_var, value in funcvars.items():
            self.source_vars[ssa_var] = value

    def visit_MLIL_SET_VAR_SSA(self, expr):

        if expr in self.visited:
            return

        dest = expr.dest
        src = self.visit(expr.src)

        if self.is_tainted(src):
            self.tainted_vars[dest] = src
            self.visited.append(expr)

            self.log_untrusted_ptr(expr, dest)

            refs = self.get_var_statements(expr, dest)
            for ref in refs:
                self.visit(ref)

        elif self.is_pointer(src):
            self.source_vars[dest] = src
            self.visited.append(expr)

            dest_refs = expr.function.get_ssa_var_uses(dest)
            for ref in dest_refs:
                self.visit(ref)

    def visit_MLIL_SET_VAR_SSA_FIELD(self, expr):
        self.visit_MLIL_SET_VAR_SSA(expr)

    def visit_MLIL_VAR_SSA(self, expr):
        ssa_var = expr.src

        if ssa_var in self.source_vars:
            return self.source_vars[ssa_var]

        elif ssa_var in self.tainted_vars and self.is_reachable(ssa_var, expr):
            return self.tainted_vars[ssa_var]

    def visit_MLIL_VAR_SSA_FIELD(self, expr):
        return self.visit_MLIL_VAR_SSA(expr)

    def visit_MLIL_LOAD_SSA(self, expr):

        if expr in self.visited:
            return

        for ssa_var in expr.src.vars_read:

            if ssa_var in self.source_vars:
                src = self.visit(expr.src)
                size = expr.size
                
                if self.is_pointer(src) and configsrcfunc.check_src(src, size):
                    return [src, size]

        #NOTE: When a tainted var is in MLIL_LOAD_SSA, we are not propogating 

    def visit_MLIL_ADD(self, expr):

        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if self.is_tainted(left) or self.is_tainted(right):
            return self.taint_marker

        # For handling pointer arithmetic operations.
        if self.is_pointer(left) and self.is_pointer(right):
            return (left + right)

    def visit_MLIL_AND(self, expr):

        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if self.is_tainted(left) or self.is_tainted(right):
            if expr.possible_values.type in (RegisterValueType.UnsignedRangeValue, RegisterValueType.SignedRangeValue):
                upper = expr.possible_values.ranges[0].end
                lower = expr.possible_values.ranges[0].start
                
                if upper > config.ALLOW_VAL:
                    return self.taint_marker

            else: return self.taint_marker

        # For handling pointer arithmetic operations.
        if self.is_pointer(left) and self.is_pointer(right):
            return (left & right)

    def visit_MLIL_LSR(self, expr):

        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if self.is_tainted(left) or self.is_tainted(right):
            
            if ((expr.right.operation == MediumLevelILOperation.MLIL_CONST) and
                        config.LSR_RANGE and (right > config.LSR_RANGE)):
                    return

            elif expr.possible_values.type in (RegisterValueType.UnsignedRangeValue, RegisterValueType.SignedRangeValue):
                upper = expr.possible_values.ranges[0].end
                lower = expr.possible_values.ranges[0].start

                if upper > config.ALLOW_VAL:
                    return self.taint_marker
            
            else: return self.taint_marker

    def visit_MLIL_MUL(self, expr):

        left = self.visit(expr.left)
        right = self.visit(expr.right)

        if self.is_tainted(left) or self.is_tainted(right):

            if ((expr.right.operation == MediumLevelILOperation.MLIL_CONST) and
                        config.MUL_RANGE and (right > config.MUL_RANGE)):
                    return
                
            else: return self.taint_marker

    def visit_MLIL_LOW_PART(self, expr):

        src = self.visit(expr.src)

        if self.is_tainted(src):
            return self.taint_marker

    def visit_MLIL_NEG(self, expr):

        src = self.visit(expr.src)

        if self.is_tainted(src):
            return self.taint_marker

    def visit_MLIL_NOT(self, expr):

        src = self.visit(expr.src)

        if self.is_tainted(src):
            return self.taint_marker

    def visit_MLIL_CONST(self, expr):
        return expr.constant

    def visit_MLIL_ZX(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_SX(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_VAR_PHI(self, expr):

        if expr in self.visited:
            return

        for ssa_var in expr.src:
            if ssa_var in self.tainted_vars and self.is_reachable(ssa_var, expr):
                self.tainted_vars[expr.dest] = self.taint_marker
                self.visited.append(expr)

                refs = self.get_var_statements(expr, expr.dest)
                for ref in refs:
                    self.visit(ref)
                # NOTE: Only one of the source variable has to be tainted to
                # mark the destination variable as tainted. Hence we break.
                break

    def visit_GENERIC(self, expr):

        # NOTE:This is a generic implemetation for handling taint propagation
        # in multiple MLIL operations. Break them separately as necessary.

        if hasattr(expr, "left") and hasattr(expr, "right"):
            left = self.visit(expr.left)
            right = self.visit(expr.right)

            if self.is_tainted(left) or self.is_tainted(right):
                return self.taint_marker
    
    def is_reachable(self, var, expr):
        if self.function_mlilssa[expr.instr_index] in self.var_def_uses[var]["refs"]:
            return True

    def is_tainted(self, var):
        return True if isinstance(var, list) else False

    def is_pointer(self, var):
        return True if isinstance(var, int) else False

    def get_var_statements(self, definition, ssa_var, arg_var = False):

        constraint_blocks = set()
        interesting_blocks = set()
        
        self.var_def_uses.setdefault(ssa_var, dict())
        
        pruned_refs = list()
        sink_blocks = dict()

        refs = definition.function.get_ssa_var_uses(ssa_var)
        basic_blocks = self.refs_to_basic_blocks(definition, refs)

        for ref in refs:
            self.get_constrained_blocks(ref, constraint_blocks, ssa_var)

        self.var_def_uses[ssa_var]["constraint_blocks"] = constraint_blocks
        self.var_def_uses[ssa_var]["region_blocks"] = self.get_region_blocks(self.graph, ssa_var)

        if len(constraint_blocks) == 0:
            self.var_def_uses[ssa_var]["constraint"] = False
            subgraph = self.graph.copy()
            self.var_def_uses[ssa_var]["subgraph"] = subgraph
            reachable_blocks = basic_blocks.keys()
        else:
            self.var_def_uses[ssa_var]["constraint"] = True
            subgraph = self.get_constrained_subgraph(constraint_blocks)
            self.var_def_uses[ssa_var]["subgraph"] = subgraph
            reachable_blocks = self.get_reachable_blocks(definition, ssa_var, basic_blocks)

        for blk, stmts in basic_blocks.items():
            if blk in reachable_blocks:
                pruned_refs += stmts
                self.get_sink_blocks(blk, stmts, sink_blocks)
            else:
                for stmt in stmts:
                    if stmt.operation not in operations.MLIL_SET_VARS:
                        continue
                    vars_read = stmt.src.vars_read
                    if len(set(vars_read)) == 1 and vars_read[0] == ssa_var:
                        self.visited.append(stmt)

        # NOTE: Remove definition from refs. When a PHI function is used in a loop, it is
        # possible that definition site can also be a reference site. Skip those entries.
        # e.g. a#2 = ϕ(a#0, a#1, a#2)
        while definition in pruned_refs and not arg_var:
            pruned_refs.remove(definition)

        self.var_def_uses[ssa_var]["def"] = definition
        self.var_def_uses[ssa_var]["refs"] = pruned_refs
        self.var_def_uses[ssa_var]["sink_blocks"] = sink_blocks

        return pruned_refs

    def get_sink_blocks(self, reachable_block, stmts, sink_blocks):

        for stmt in stmts:
            self.get_interesting_blocks(stmt, sink_blocks)

    def check_vars(self, expr):
        return set(expr.vars_read).intersection(self.tainted_vars)

    def get_interesting_blocks(self, expr, sink_blocks):

        for fields in MediumLevelILInstruction.ILOperations[expr.operation]:
            x, y = fields
            if y == "expr":
                self.get_interesting_blocks(getattr(expr, x), sink_blocks)

        if ((expr.operation == MediumLevelILOperation.MLIL_STORE_SSA and self.check_vars(expr.dest)) or
            (expr.operation == MediumLevelILOperation.MLIL_LOAD_SSA and self.check_vars(expr.src)) or
            (expr.operation in operations.MLIL_CALLS and self.check_vars(expr)) or
            (expr.operation == MediumLevelILOperation.MLIL_IF and self.check_loop_operation(expr) and self.check_vars(expr))):

            instr = self.function_mlilssa[expr.instr_index]
            if expr.il_basic_block not in sink_blocks:
                sink_blocks[expr.il_basic_block] = [instr]
            elif instr not in sink_blocks[expr.il_basic_block]:
                sink_blocks[expr.il_basic_block].append(instr)

