from binaryninja import *
from . import config
from . import operations
import logging
import copy

class MLILMemory():

    def get_stack_vars(self, expr, ssa_var, alias_vars):

        # Recursively fetch SSA variables related to a stack variable until MLIL_ADDRESS_OF
        vardef = expr.function.get_ssa_var_definition(ssa_var)

        if vardef.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
            return

        src_vars = vardef.src.vars_read

        for var in src_vars:
            alias_vars.append(var)
            self.get_stack_vars(expr, var, alias_vars)

    def get_phi_vars(self, expr):

        # When a PHI function is used in a loop, it is possible that definition site
        # can also be a reference site. Skip those entries e.g. a#2 = ϕ(a#0, a#1, a#2)
        destvar = expr.dest
        srcvars = expr.src

        if destvar in srcvars:
            srcvars.remove(destvar)

        return srcvars

    def get_memory_vars(self, expr, ssa_var, memory_vars):

        vardef = expr.function.get_ssa_var_definition(ssa_var)

        # When there is no definition site, the SSA variable is an argument
        if vardef == None:
            return

        # Variable is assigned as a return value of a call instruction
        if vardef.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            return

        if vardef.operation == MediumLevelILOperation.MLIL_VAR_PHI:
            src_vars = vardef.src
        else:
            src_vars = vardef.src.vars_read

        for var in src_vars:
            if var not in memory_vars:
                # Tracking back SSA variables may lead to vars with stack source. We will
                # skip these vars as we have the SSA vars associated with the stack variable.
                if hasattr(var, "version"):
                    memory_vars.append(var)
                    self.get_memory_vars(expr, var, memory_vars)

    def get_phi_varinfo(self, expr, explore = False):

        srcvars = self.get_phi_vars(expr)
        varinfos = list()

        for ssavar in srcvars:
            if explore:
                varinfo = self.getvarex(expr, ssavar)
            else:
                varinfo = self.getvar(ssavar)

            if varinfo is not None:
                varinfos.append(varinfo)

        # When there are no resolved variable create a dynamic node.
        if len(varinfos) == 0:
            return None

        # When there is PHI function, choose a value pointing to allocated memory,
        # else choose any available memory pointer.
        for varinfo in varinfos:
            if varinfo["vartype"] == config.MEMALLOC:
                srcvarinfo = varinfo
        else:
            srcvarinfo = varinfos[0]

        return srcvarinfo

    def setvar(self, destvar, srcnode, srcoffset, srcvartype):

        srcvarinfo = dict(node = srcnode, offset = srcoffset, vartype = srcvartype)
        if srcvartype == config.GLOBAL:
            self.vars[destvar] = srcvarinfo
        else:
            destvarindex = self.get_var_index(destvar)
            self.vars[destvarindex] = srcvarinfo

    def setvarinfo(self, destvar, srcvarinfo):

        if srcvarinfo["vartype"] == config.GLOBAL:
            self.vars[destvar] = srcvarinfo
        else:
            destvarindex = self.get_var_index(destvar)
            self.vars[destvarindex] = srcvarinfo

    def getvar(self, ssavar):

        varindex = self.get_var_index(ssavar)
        if varindex in self.vars:
            return self.vars[varindex]
        # Global memory is not associated with any function.
        elif ssavar in self.vars:
            return self.vars[ssavar]

    def getvarex(self, expr, var):
        varinfo = self.getvar(var)

        if varinfo is None:
            varinfo = self.explore_memory(expr, var)

        return varinfo

    def get_basevar_offset(self, expr):

        if expr.operation in [MediumLevelILOperation.MLIL_CONST_PTR, MediumLevelILOperation.MLIL_EXTERN_PTR]:
            basevar, basevar_expr = hex(expr.constant), expr
            offset = 0
        
        elif expr.operation is MediumLevelILOperation.MLIL_VAR_SSA:
            basevar, basevar_expr = expr.src, expr
            offset = 0

        elif expr.operation is MediumLevelILOperation.MLIL_ADD:
            lhs = expr.left

            if lhs.operation is MediumLevelILOperation.MLIL_ADD:
                basevar, basevar_expr = lhs.left.vars_read[0], lhs.left
            elif lhs.operation is MediumLevelILOperation.MLIL_VAR_SSA:
                basevar, basevar_expr = lhs.src, lhs
            elif lhs.operation is MediumLevelILOperation.MLIL_CONST_PTR:
                basevar, basevar_expr = hex(lhs.constant), lhs

            if expr.right.operation == MediumLevelILOperation.MLIL_CONST:
                offset = expr.right.constant
            else: #TODO: Possibly process unresolved vars better in future.
                offset = 0

        return basevar, basevar_expr, offset

    def edge_exists(self, srcnode, destnode, write_offset, points_offset):
        edge_data = self.data_graph.get_edge_data(srcnode, destnode)

        if edge_data is not None:

            for edge in edge_data.values():
                if write_offset == edge["write_offset"] and points_offset == edge["points_offset"]:
                    return True
            else: return False

        else: return False

    def add_data_edge(self, srcnode, destnode, write_offset, points_offset):

        if not self.edge_exists(srcnode, destnode, write_offset, points_offset):
            self.data_graph.add_edge(srcnode, destnode, write_offset = write_offset, points_offset = points_offset)

    def explore_memory(self, expr, ssavar):

        # Handle loop SSA vars in PHI functions.
        if ssavar in self.loopvars:
            self.create_dynamic_node(expr, ssavar)
            return self.getvar(ssavar)
        self.loopvars.append(ssavar)

        vardef = expr.function.ssa_form.get_ssa_var_definition(ssavar)

        # Variable is coming as argument and does not have definition site or
        # Variable is assigned from a function call like malloc.
        if vardef is None or vardef.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            self.create_dynamic_node(expr, ssavar)

        elif vardef.operation == MediumLevelILOperation.MLIL_VAR_PHI:

            srcvarinfo = self.get_phi_varinfo(vardef, True)
            if srcvarinfo is None:
                self.create_dynamic_node(expr, ssavar)
            else:
                self.setvarinfo(ssavar, srcvarinfo)

        elif vardef.operation in operations.MLIL_SET_VARS:
            srcvarinfo = self.visit(vardef.src)
            
            # srcvarinfo may return None when a memory load is not resolved.
            if srcvarinfo is None:
                node = self.create_dynamic_node(expr, ssavar)

                # Connect the new dynamic node to the failed load resolution instruction.
                if (vardef.src.operation == MediumLevelILOperation.MLIL_LOAD_SSA and
                        vardef.src.size is self.bv.address_size):

                    basevar, basevar_expr, offset = self.get_basevar_offset(vardef.src.src)
                    basevarinfo = self.getvar(basevar)
                    self.add_data_edge(basevarinfo["node"], node, offset, 0)
            # srcvarinfo may return 0 for NULL initialization.
            elif self.is_constant(srcvarinfo):
                self.create_dynamic_node(expr, ssavar)
            else:
                self.setvarinfo(ssavar, srcvarinfo)
        
        elif vardef.operation in [MediumLevelILOperation.MLIL_INTRINSIC_SSA]:
            #NOTE: Evaluate necessity of MLIL_ADDRESS_OF and MLIL_INTRINSIC_SSA.
            self.log_message("Expression not explored : %s %s @ 0x%x" % (vardef.operation.name, vardef, vardef.address), logging.INFO)

        else: raise NotImplementedError("Expression not explored : %s %s @ 0x%x" % (vardef.operation.name, vardef, vardef.address))

        self.visit_refs(expr, ssavar)

        # Rest the loop tracking when explore_memory returns
        self.loopvars = list()

        return self.getvar(ssavar)

    def load_from_alloc(self, expr):

        self.log_message("Read from allocated memory %s @ 0x%x" % (expr, expr.address), logging.INFO)

        config.stacktrace[-1][1] = expr.address
        stacktrace = copy.deepcopy(config.stacktrace)
        key = self.generate_index(stacktrace, expr.address)
        self.log_blks[key] = [config.READ, expr, stacktrace]
        self.visited[expr] = 0

    def store_in_alloc(self, expr):
        
        self.log_message("Write to allocated memory %s @ 0x%x" % (expr, expr.address), logging.INFO)
        
        config.stacktrace[-1][1] = expr.address
        stacktrace = copy.deepcopy(config.stacktrace)
        key = self.generate_index(stacktrace, expr.address)
        self.log_blks[key] = [config.WRITE, expr, stacktrace]
        self.visited[expr] = 0

    def store_in_stack(self, expr, srcvarinfo, destvarinfo):
        destvar = expr.dest.src
        destoffset = expr.dest.value.value
        self.setvar(destvar, hex(self.function.start), destoffset, config.STACK)
        self.add_data_edge(hex(self.function.start), srcvarinfo["node"], destoffset, srcvarinfo["offset"])
        self.visited[expr] = 0
        self.visit_stack_access(expr, destvar)
        #TODO: Explore get_stack_var_at_frame_offset() and get_var_uses()

    def store_in_global(self, expr, srcvarinfo, destvarinfo):

        # setvar is not necessary since MLIL_CONST_PTR handler creates the vars.
        self.add_data_edge(destvarinfo["node"], srcvarinfo["node"], 0, points_offset = srcvarinfo["offset"])
        self.visited[expr] = 0
        self.visit_global_access(expr.dest.value.value)

    def store_in_dynamic(self, expr, srcvarinfo, destvarinfo, destoffset):

        # Associate the memory with a base SSA variable.
        destvar = expr.dest.vars_read[0]
        self.setvar(destvar, destvarinfo["node"], destvarinfo["offset"], config.DYNAMIC)
        self.add_data_edge(destvarinfo["node"], srcvarinfo["node"], destvarinfo["offset"] + destoffset, srcvarinfo["offset"])
        self.visited[expr] = 0
        self.visit_memory_access(expr, destvar)

    def returns_alloc(self, expr):
        
        self.log_message("Allocation in return statement @ 0x%x" % (expr.address), logging.INFO)
        
        if self.allocexpr is not None:
            if self.allocexpr.function == expr.function:
                self.log_message("Potential allocator wrapper function %s @ 0x%x" 
                                        % (self.function_name, self.function.start), logging.CRITICAL)

    def free_alloc(self, expr, param):
        
        self.log_message("Allocation freed @ 0x%x" % (expr.address), logging.CRITICAL)
        # Overwrites the dictionary entry self.log_blks added in call_with_alloc_arg 
        # function, when the CALL is also deallocation function.
        
        config.stacktrace[-1][1] = expr.address
        stacktrace = copy.deepcopy(config.stacktrace)
        key = self.generate_index(stacktrace, expr.address)
        self.log_blks[key] = [config.FREE, expr, stacktrace]

        # NOTE: Detect potential deallocator functions
        if self.function.type.return_value.get_string() == "void" or param.value.type == RegisterValueType.EntryValue:
            self.log_message("Potential deallocator wrapper function %s @ 0x%x" 
                                        % (self.function_name, self.function.start), logging.CRITICAL)

    def call_with_alloc_arg(self, expr, param, symbol):
        
        if symbol is None:
            self.log_message("Function call made using allocated memory @ 0x%x" % (expr.address), logging.INFO)
        else:
            self.log_message("Function %s() call made using allocated memory @ 0x%x" % (symbol, expr.address), logging.INFO)

        config.stacktrace[-1][1] = expr.address
        stacktrace = copy.deepcopy(config.stacktrace)
        key = self.generate_index(stacktrace, expr.address)
        self.log_blks[key] = [config.CALL, expr, stacktrace]
