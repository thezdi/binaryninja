from binaryninja import *
from . import tracergraph
from . import bnilvisitor
from . import config
from . import operations
from . import helpers
from . import calleeargs
from . import mlilmemory
import logging
import networkx as nx

class MLILTracer(bnilvisitor.BNILVisitor, calleeargs.CalleeArgs, mlilmemory.MLILMemory, tracergraph.TracerGraph, helpers.Helpers):

    def __init__(self, bv, function, vars_to_track, allocexpr = None, resolved_vars = None, 
                                                data_graph = None, control_graph = None, log_blks = None):
        super(MLILTracer, self).__init__()
       
        if log_blks is None:
            self.log_blks = dict()
        else: 
            self.log_blks = log_blks

        self.bv = bv

        self.visited = dict()

        # The allocexpr is the reference expression where allocator is called. In case of functions like realloc,
        # the same call could both free and allocate the memory. This may create a loop during analysis, because
        # the variable returned by realloc may relate back to the argument passed to realloc. So we add it as 
        # marked to prevent this loop.
        self.allocexpr = allocexpr
        if allocexpr is not None:
            self.visited[allocexpr] = 0

        self.function = function 
        typeinfo, demangled_name = demangle_gnu3(bv.arch, self.function.name)
        self.function_name = demangled_name
      
        # A list of details for static call stack. First is function address and second is expression address.
        # Intially, expression address is set to None and gets updated when a call is made.
        func_details = [self.function.start, None]
        config.stacktrace.append(func_details)

        # When tracing the function calls, create a graph of the function as control graph.

        if not control_graph:
            self.control_graph = dict()
            self.control_graph[self.function] = self.get_function_il_graph(self.function.mlil, self.allocexpr)
        else:
            self.control_graph = control_graph
            if self.function not in self.control_graph:
                self.control_graph[self.function] = self.get_function_il_graph(self.function.mlil, self.allocexpr)

        # Data graph connects all the allocations during tracing. This includes the stack, heap and the global
        # memory. When a function is traced add a node to represent its stack.
        if not data_graph:
            self.data_graph = nx.MultiDiGraph()
        else:
            self.data_graph = data_graph
        # TODO: When a function recurses it may end up using the same data graph node. Check if it necessary
        # to create a unique node in these circumstances.
        self.data_graph.add_node(hex(self.function.start), nodetype = config.STACK, color = "green")

        if resolved_vars is None:
            self.vars = dict()
        else: 
            self.vars = resolved_vars

        self.tracking_vars = vars_to_track

        # Keep track of variables visited during explore_memory() to prevent recursion.
        self.loopvars = list()

    def __del__(self):
        
        config.stacktrace.pop()

    def trace(self):

        # NOTE: Detect recursion using the stack trace.
        if self.has_recursion(config.stacktrace):
            self.log_message("Recursion noticed in %s function" % (self.function_name), logging.WARNING)
            return
        
        if self.function.mlil.ssa_form is None:
            return

        if self.allocexpr is not None:
            self.log_message("Allocation @ 0x%x in %s" % (self.allocexpr.address, self.function_name), logging.WARNING)

            # Handle allocator functions which are part of tailcall.
            if (self.allocexpr.operation == MediumLevelILOperation.MLIL_TAILCALL_SSA and 
                self.allocexpr.function.source_function.symbol.type is not SymbolType.ImportedFunctionSymbol):

                self.returns_alloc(self.allocexpr)
                return
            
            destvar = self.allocexpr.vars_written[0]
            # Create a data node for the allocation that's being tracked. Associate a node to a node type.
            self.data_graph.add_node(config.MEMALLOC, nodetype = config.MEMALLOC, color = "red")
            # Associate the variable holding address of allocated memory to a node as well an offset. For a newly
            # allocated memory the variable points to offset 0.
            self.setvar(destvar, config.MEMALLOC, 0, config.MEMALLOC)

        # Track all the uses of the variable pointing to allocated memory.
        expr = [x for x in self.function.mlil.ssa_form.instructions][0]
        for var in self.tracking_vars:
            for var_ref in expr.function.get_ssa_var_uses(var):
                self.visit(var_ref)

        # NOTE: Limit the depth of analysis. Otherwise we may run out of resources.
        if len(config.stacktrace) >= config.max_depth:
            return
        
        # Trace the callees of the function which calls the allocator.
        self.visit_callees()

    def trace_allocator(self):

        # Perform the first iteration to build graph and variable info in the order to instructions visited by refs.
        config.trace_graph = True
        self.trace()
    
        # Perform second iteration using the graph built from first iteration. This is not a optimal solution,
        # but works without any code changes to first iteration. Split operations between iterations to improve performance.
        config.trace_graph = False
        # Reset the visited instructions list.
        self.visited = dict()
        self.trace()

    def visit_refs(self, expr, var):

        refs = expr.function.get_ssa_var_uses(var)
        for ref in refs:
            self.visit(ref)

    def visit_stack_access(self, expr, var):

        # Get the ssavars related to the stack offset and visit instructions.
        alias_vars = list()
        alias_vars.append(var)
        self.get_stack_vars(expr, var, alias_vars)

        for alias in alias_vars:
            offset = expr.get_ssa_var_possible_values(alias).offset
            self.setvar(alias, hex(self.function.start), offset, config.STACK)
            self.visit_refs(expr, alias)

    def visit_memory_access(self, expr, var):

        memory_vars = list()
        memory_vars.append(var)
        self.get_memory_vars(expr, var, memory_vars)
        for var in memory_vars:
            self.visit_refs(expr, var)

    def visit_global_access(self, address):
        
        #NOTE: Currently this is limited to single function.
        for refs in self.bv.get_code_refs(address):
            if refs.mlil != None and refs.mlil.ssa_form != None and refs.function == self.function:
                self.visit(refs.mlil.ssa_form)

    def visit_MLIL_ADDRESS_OF(self, expr):
        varinfo = dict(node = hex(self.function.start), offset = expr.value.value, vartype = config.STACK)
        return varinfo

    def visit_MLIL_CONST(self, expr):
        return expr.constant

    def visit_MLIL_CONST_PTR(self, expr):

        if expr.constant == 0:
            self.log_message("NULL pointer resolved @ 0x%x in %s" % (expr.address, self.function_name), logging.WARNING)

        ptr = hex(expr.constant)
        
        if ptr not in self.vars:
            # Global memory is not associated with functions like SSA vars. Therefore assign them
            # directly instead of using setvar()
            self.vars[ptr] = dict(node = ptr, offset = 0, vartype = config.GLOBAL)
            self.data_graph.add_node(ptr, nodetype = config.GLOBAL, color = "black")
        return self.vars[ptr]

    def visit_MLIL_ADD(self, expr):

        if expr in self.visited:
            return self.visited.get(expr)

        leftvarinfo = self.visit(expr.left)
        rightvarinfo = self.visit(expr.right)
        basevarinfo = None

        # When any of the variable is allocated memory, just return the varinfo.
        # Offsets does not matter in this case. When the variable is not allocated
        # memory, pick any of the available variable info, preferrably left.
        if leftvarinfo is not None:
            basevarinfo = leftvarinfo
            if leftvarinfo["vartype"] == config.MEMALLOC:
                return leftvarinfo
        
        if rightvarinfo is not None and not self.is_constant(rightvarinfo):
            basevarinfo = leftvarinfo or rightvarinfo
            if rightvarinfo["vartype"] == config.MEMALLOC:
                return rightvarinfo
        
        if basevarinfo is None: return

        if expr.right.operation == MediumLevelILOperation.MLIL_CONST:
            offset = self.visit(expr.right)
        else: #TODO: Possibly process unresolved vars better in future.
            offset = 0

        varinfo = dict(node = basevarinfo["node"], offset = basevarinfo["offset"] + offset,
                                                        vartype = basevarinfo["vartype"])
        self.visited[expr] = varinfo
        return varinfo

    def visit_MLIL_SUB(self, expr):
      
        if expr in self.visited:
            return self.visited.get(expr)
       
        # A pointer is subtracted from another. In this case just try to propagate allocated
        # memory. But this may lead to false positive results.
        leftvarinfo = self.visit(expr.left)
        rightvarinfo = self.visit(expr.right)
        varinfo = None

        if leftvarinfo is not None:
            if leftvarinfo["vartype"] == config.MEMALLOC:
                varinfo = leftvarinfo
        elif rightvarinfo is not None and not self.is_constant(rightvarinfo):
            if rightvarinfo["vartype"] == config.MEMALLOC:
                varinfo = rightvarinfo

        if varinfo is None:
            varinfo = leftvarinfo or rightvarinfo
        
        return varinfo
   
    def visit_MLIL_SBB(self, expr):
        return self.visit_MLIL_SUB(expr)

    def visit_MLIL_AND(self, expr):
        # Handle pointer alignment operation. Just propagate the pointer.
        basevarinfo = self.visit(expr.left)
        return basevarinfo

    def visit_MLIL_SET_VAR_SSA(self, expr):

        if expr in self.visited:
            return

        if expr.src.operation == MediumLevelILOperation.MLIL_CONST:
            self.visited[expr] = 0
            return

        destvar = expr.dest
        srcinfo = self.visit(expr.src)
        # Propagate only pointers. So use size information to filter out some instructions.
        # Type information may filter out further, but accuracy may not be reliable.
        if destvar.type.width is not self.bv.address_size and config.check_type_size:
            self.visited[expr] = 0
            return

        # Possible when read is from allocated memory.
        if srcinfo is None or srcinfo == 0: return

        self.setvarinfo(destvar, srcinfo)
        
        # When the destination variable is a stack variable, create a graph edge.
        if destvar.var.source_type == VariableSourceType.StackVariableSourceType:
            self.add_data_edge(hex(self.function.start), srcinfo["node"], 
                                destvar.var.storage, srcinfo["offset"])
        
        self.visited[expr] = 0
        self.visit_refs(expr, destvar)

    def visit_MLIL_VAR_SSA(self, expr):
        varinfo = self.getvar(expr.src)
        
        if varinfo is None:
            varinfo = self.explore_memory(expr, expr.src)

        return varinfo

    def visit_MLIL_VAR_SSA_FIELD(self, expr):
        return self.visit_MLIL_VAR_SSA(expr)

    def visit_MLIL_SET_VAR_SSA_FIELD(self, expr):
        self.visit_MLIL_SET_VAR_SSA(expr)
 
    def visit_MLIL_LOAD_STRUCT_SSA(self, expr):
    
        if expr in self.visited:
            return self.visited.get(expr)

        srcinfo = self.visit(expr.src)
        off_srcinfo = srcinfo.copy()
        off_srcinfo["offset"] = srcinfo["offset"] + expr.offset
        self.visited[expr] = off_srcinfo
        return off_srcinfo

    def visit_MLIL_STORE_STRUCT_SSA(self, expr):
        
        if expr in self.visited:
            return
        
        destinfo = None
        # We do not resolve stack vars, instead directly use the offset info later.
        if expr.dest.value.type is not RegisterValueType.StackFrameOffset:
            destinfo = self.visit(expr.dest)
            if not destinfo: return
       
        # An allocated memory is written to. Log this info irrespective of the source. 
        if self.is_allocmem(expr.dest):
            self.store_in_alloc(expr)
            return

        # Resolve the source to create memory links.
        srcinfo = self.visit(expr.src)
        if not srcinfo: return

        # Skip constant writes as they do not create links.
        if self.is_constant(srcinfo): return

        if self.is_stackmem(expr.dest):
            self.store_in_stack(expr, srcinfo, destinfo)
        elif self.is_globalmem(expr.dest):
            self.store_in_global(expr, srcinfo, destinfo)
        else:
            # Pass the structure offset information.
            self.store_in_dynamic(expr, srcinfo, destinfo, expr.offset)

    def visit_MLIL_VAR_ALIASED(self, expr):
        varinfo = self.getvarex(expr, expr.src)
        return varinfo

    def visit_MLIL_LOAD_SSA(self, expr):
     
        if expr in self.visited:
            return self.visited.get(expr)
     
        # When loading from stack, fetch the stack offset and get the associated edge.
        if expr.src.value.type == RegisterValueType.StackFrameOffset:
            offset = expr.src.value.value
            node = hex(self.function.start)
            edge = self.get_edge(node, offset)
            if edge is None:
                srcvarinfo = self.visit(expr.src)
                edge = self.get_edge(srcvarinfo["node"], srcvarinfo["offset"])

        # Otherwise resolve the variable and fetch the edge info.
        else:
            basevar, basevar_expr, offset = self.get_basevar_offset(expr.src)
            srcvarinfo = self.visit(basevar_expr)
            edge = self.get_edge(srcvarinfo["node"], srcvarinfo["offset"] + offset)

        # An allocated memory is read from. Log this info and return. Edge will be None
        # since we do not create links during write to allocated memory.
        if self.is_allocmem(expr.src):
            self.load_from_alloc(expr)

            # TODO: Evaluate what to return here. Currently it returns None during edge check.
            # When propagate_read is enabled return a dummy allocated varinfo.
            if config.propagate_reads:
                varinfo = dict(node = config.MEMALLOC, offset = 0, vartype = config.MEMALLOC)
                self.visited[expr] = varinfo
                return varinfo

        # When edge is not resolved or load is from allocated memory, just return.
        if edge is None: return None 
            
        srcnode, destnode, attr = edge
        varinfo = dict(node = destnode, offset = attr["points_offset"], 
                    vartype = self.data_graph.nodes[destnode]["nodetype"])
        
        self.visited[expr] = varinfo

        return varinfo

    def visit_MLIL_STORE_SSA(self, expr):
      
        if expr in self.visited: 
            return

        destinfo = None
        # We do not resolve stack vars, instead directly use the offset info later.
        if expr.dest.value.type is not RegisterValueType.StackFrameOffset:
            basevar, basevar_expr, offset = self.get_basevar_offset(expr.dest)
            destinfo = self.visit(basevar_expr)
            if not destinfo: return 

        # An allocated memory is written to. Log this info irrespective of the source. 
        if self.is_allocmem(expr.dest):
            self.store_in_alloc(expr)
            return
    
        # Resolve the source to create memory links.
        srcinfo = self.visit(expr.src)
        if not srcinfo: return
       
        # Skip constant writes as they do not create links.
        if self.is_constant(srcinfo): return

        if self.is_stackmem(expr.dest):
            self.store_in_stack(expr, srcinfo, destinfo)
        elif self.is_globalmem(expr.dest):
            self.store_in_global(expr, srcinfo, destinfo)
        else:
            self.store_in_dynamic(expr, srcinfo, destinfo, offset)

    def visit_MLIL_ZX(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_SX(self, expr):
        return self.visit(expr.src)

    def visit_MLIL_VAR_PHI(self, expr):

        if expr in self.visited: 
            return

        destvar = expr.dest
        srcvarinfo = self.get_phi_varinfo(expr)

        if srcvarinfo is None: return

        self.setvarinfo(destvar, srcvarinfo)
        self.visited[expr] = 0
        self.visit_refs(expr, destvar)

    def visit_MLIL_SET_VAR_ALIASED(self, expr):

        if expr in self.visited: 
            return

        self.visit_MLIL_SET_VAR_SSA(expr)

        destvar = expr.dest.var
        refs = expr.function.get_var_uses(destvar)
        for ref in refs:
            self.visit(ref)
        
    def visit_MLIL_RET(self, expr):

        if expr in self.visited: 
            return
        
        for value in expr.src:
            if value.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                varinfo = self.getvar(value.src)
                if varinfo is not None and varinfo["vartype"] == config.MEMALLOC:
                    self.returns_alloc(expr)
                    self.visited[expr] = 0
                    break

    def visit_GENERIC(self, expr):

        # Returns nothing. Just log if there is a memory load operation.
        if expr in self.visited: 
            return
        
        if expr.operation is MediumLevelILOperation.MLIL_IF:
            # Handle conditions like if (cond:0_1#1)
            if hasattr(expr.condition, "left"):
                self.visit(expr.condition.left)
                self.visit(expr.condition.right)
        elif expr.operation in operations.MLIL_CMPS:
            self.visit(expr.left)
            self.visit(expr.right)
        else:
            self.log_message("Expression not evaluated : %s @ 0x%x" % (expr, expr.address), logging.INFO)

        self.visited[expr] = 0

    def visit_MLIL_CALL_SSA(self, expr):

        if expr in self.visited:
            return

        self.visited[expr] = 0
        symbol = None
        
        # Log any function call made using allocated memory as parameter. This includes indirect
        # function calls too.
        for param in expr.params:
            if param.operation is not MediumLevelILOperation.MLIL_VAR_SSA:
                continue
            varinfo = self.getvar(param.src)
            if varinfo is not None and varinfo["vartype"] == config.MEMALLOC:
                # When the call target is known, resolve and check the destination
                if expr.dest.operation in [MediumLevelILOperation.MLIL_CONST_PTR, MediumLevelILOperation.MLIL_EXTERN_PTR]:
                    symbol = self.bv.get_symbol_at(expr.dest.constant)
                    # Check whether destination is call to deallocator function or other functions
                    # and log them accordingly.
                    if symbol is not None:
                        if symbol.name in config.dealloc_func:
                            self.free_alloc(expr, param)
                            return
                        else:
                            self.call_with_alloc_arg(expr, param, symbol.name)
                else:
                    self.call_with_alloc_arg(expr, param, None)
                    return

    def visit_MLIL_TAILCALL_SSA(self, expr):
        self.visit_MLIL_CALL_SSA(expr)

    def visit_callees(self):

         for call_site in self.function.call_sites:
            expr = call_site.mlil.ssa_form

            # There are instances where reps instruction gets translated to function call in MLIL.
            # Therefore check if the operation is MLIL_CALL_SSA before fetching destination of call.
            if (expr.operation in [MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA] and 
                expr.dest.operation == MediumLevelILOperation.MLIL_CONST_PTR):
                symbol = self.bv.get_symbol_at(expr.dest.constant)
            else: continue
            
            # Skip dealloction function calls.
            if symbol is not None and symbol.name in config.dealloc_func:
                continue
            
            # Ignore the library functions and perform an interprocedural analysis.
            elif symbol is None or symbol.type == SymbolType.FunctionSymbol:
                callee_function = self.bv.get_function_at(expr.dest.constant)
                args = self.get_args_to_pass(callee_function, expr)

                if not args: continue

                # Update the caller information in stack trace with expression address
                config.stacktrace[-1][1] = expr.address

                callee = MLILTracer(self.bv, callee_function, list(args.keys()), resolved_vars = self.vars, 
                        data_graph = self.data_graph, control_graph = self.control_graph, log_blks = self.log_blks)
        
                if callee.function is None:
                    del callee
                    continue
                
                self.log_message("[*] Exploring function call %s @ 0x%x" 
                                            % (callee_function.name, expr.address), logging.INFO)
                callee.set_function_args(args)
                callee.trace()
                del callee
