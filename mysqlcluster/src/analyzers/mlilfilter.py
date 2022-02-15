from binaryninja import *
from . import operations
from . import config
import logging

class MLILFilter():

    def get_function_loops(self, function):

        loops = dict()

        for expr in function.hlil.instructions:
            if expr.operation in (HighLevelILOperation.HLIL_DO_WHILE,
                                 HighLevelILOperation.HLIL_WHILE, HighLevelILOperation.HLIL_FOR):
                loops[expr.condition.address] = [expr, expr.address]

        return loops

    def filter_vars(self):
        
        self.build_ssavar_dependency_graph()

        for var in self.tainted_vars:
            if self.var_def_uses[var]["constraint"]:
                self.check_var_relations(var)

        for var in self.tainted_vars:

            unique_sink_blocks = dict()
            for root_vars, sink_blocks in self.var_def_uses[var]["root_vars"].items():
                unique_sink_blocks.update(sink_blocks)

            for block, stmts in unique_sink_blocks.items():
                if len(stmts) == 0:
                    continue
                for expr in stmts:
                    self.check_results(expr, var)

    def check_var_relations(self, var):
       
        visited_child_vars = list()
        visited_child_vars.append(var)

        self.parent_var = var
        child_vars = self.get_child_vars(var)

        for child_var in child_vars:
            if child_var not in visited_child_vars:
                self.check_dependent_var_for_constraints(var, child_var)
                visited_child_vars.append(child_var)

        parent_vars = self.get_parent_vars(var)
        
        for parent_var in parent_vars:

            self.parent_var = parent_var
            child_vars = self.get_child_vars(parent_var)
            child_vars.add(parent_var)
        
            for child_var in child_vars:
                if child_var not in visited_child_vars:
                    self.check_dependent_var_for_constraints(var, child_var)
                    visited_child_vars.append(child_var)
        
    def check_dependent_var_for_constraints(self, var, child_var):
        
        if self.tainted_vars[var] == self.taint_marker and config.allow_derived_vars:
            return
        
        constraint_root_vars = self.var_def_uses[var]["root_vars"]
        child_root_vars = self.var_def_uses[child_var]["root_vars"]
        
        parent_var_def = self.var_def_uses[self.parent_var]["def"]
        child_var_def = self.var_def_uses[child_var]["def"]
        
        # NOTE: Check for path from definition of parent to definition of child.
        if self.check_definition(var, parent_var_def.il_basic_block, child_var_def.il_basic_block):
           
            # NOTE: Find unique sink blocks from multiple root_vars context.
            unique_sink_blocks = dict()
            for child_root_var, sink_blocks in child_root_vars.items():
                if child_root_var in constraint_root_vars:
                    unique_sink_blocks.update(sink_blocks)

            reachable_blocks = self.get_reachable_blocks(child_var_def, var, unique_sink_blocks)
            
            for child_root_var, sink_blocks in child_root_vars.items():
                if child_root_var in constraint_root_vars:
                    
                    pruned_sink_blocks = dict()
                    for blk, stmts in sink_blocks.items():
                        if blk in reachable_blocks:
                            pruned_sink_blocks[blk] = stmts
                    
                    self.var_def_uses[child_var]["root_vars"][child_root_var] = pruned_sink_blocks
        else: 
            for child_root_var in child_root_vars:
                if child_root_var in constraint_root_vars:
                    self.var_def_uses[child_var]["root_vars"][child_root_var] = dict()

    def get_constrained_blocks(self, expr, constraint_blocks, ssa_var):
        
        for fields in MediumLevelILInstruction.ILOperations[expr.operation]:
            x, y = fields
            if y == "expr":
                self.get_constrained_blocks(getattr(expr, x), constraint_blocks, ssa_var)

        if expr.operation in operations.MLIL_CMPS and self.check_taint_filters(expr, ssa_var):
           constraint_blocks.add(expr.il_basic_block)

    def refs_to_basic_blocks(self, var_def, var_ref):

        basic_blocks = dict()

        # NOTE: Definition statement is also part of basic block.
        basic_blocks[var_def.il_basic_block] = [var_def]

        for ref in var_ref:
            if ref.il_basic_block in basic_blocks:
                if ref not in basic_blocks[ref.il_basic_block]:
                    basic_blocks[ref.il_basic_block].append(ref)
            else:
                basic_blocks[ref.il_basic_block] = [ref]

        return basic_blocks

    def check_taint_filters(self, expr, ssa_var):
        lexpr = expr.left
        rexpr = expr.right
        
        if rexpr.operation == MediumLevelILOperation.MLIL_CONST and rexpr.constant == 0:
            return False
        
        if ssa_var in lexpr.vars_read and self.check_memory_loads(lexpr):
            return False
        
        if ssa_var in rexpr.vars_read and self.check_memory_loads(rexpr):
            return False

        if ssa_var in expr.vars_read and self.check_loop_operation(expr):
            return False
        
        return True

    def check_memory_loads(self, expr):
        if expr.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
            return True
        
        for fields in MediumLevelILInstruction.ILOperations[expr.operation]:
            x, y = fields
            if y == "expr":
                return self.check_memory_loads(getattr(expr, x))
       
    def check_loop_operation(self, expr):
        if self.function_mlilssa[expr.instr_index].address in self.loops:
            return True

    def check_x86_reps(self, expr):
        if self.bv.get_disassembly(expr.address).startswith("rep"):
            return True

    # NOTE: Use when signed integer comparison is not necessarily a filter.
    def check_signed_comparison(self, expr):
        if expr.operation in operations.MLIL_SIGNED_CMPS:
            return True
