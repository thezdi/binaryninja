from binaryninja import *
from . import config
import networkx as nx
import logging

class TracerGraph():

    def get_function_il_graph(self, function, allocexpr):

        graph = nx.DiGraph()

        for blk in function.ssa_form.basic_blocks:

            graph.add_node(blk)

            for outgoing_edge in blk.outgoing_edges:
                srcnode = blk
                destnode = outgoing_edge.target
                graph.add_edge(srcnode, destnode)

            for incoming_edge in blk.incoming_edges:
                srcnode = incoming_edge.source
                destnode = blk
                graph.add_edge(srcnode, destnode)
        
        # Remove incoming edges to the basic block which has the allocator call.
        # This is done to reduce false positives involving loops. Any use of allocated 
        # memory, before the free call will not be reachable in graph and thus eliminating
        # them from results
        
        if allocexpr is not None and graph.has_node(allocexpr.il_basic_block):
            incoming_edges = list(graph.in_edges(allocexpr.il_basic_block))
            graph.remove_edges_from(incoming_edges)

        return graph

    def create_dynamic_node(self, expr, ssavar):

        # When a variable is part of PHI function or coming as an argument or as a return value of a function call or
        # from an unresolved memory load operation or from a variable initialized to NULL (which may be initialized)
        # assign a dynamic node to it and associate it with DYNAMIC type.
        node = config.DYNAMIC + str(next(config.dyncounter)) + "_" + self.get_var_index(ssavar)
        self.data_graph.add_node(node, nodetype = config.DYNAMIC, color = "blue")
        # Assume the variable points to the base i.e. offset 0
        self.setvar(ssavar, node, 0, config.DYNAMIC)
        return node

    def choose_edge(self, edges):

        for edge in edges:
            src, dest, attr = edge
            if dest == config.MEMALLOC:
                return edge
        else: return edges[0]

    def get_edge(self, node, offset):
        # Given a node and an offset, search through all edges for finding an edge with matching offset. An edge is
        # created for every memory write. Since multiple writes are possible to the same memory location, multiple
        # edges may be created. If any of the destination points to allocated memory, then prioritize that edge.
        all_edges = []

        # Assume multiple writes to same memory location, creating multiple edges
        for edge in self.data_graph.edges(node, data=True):
            src, dest, attr = edge
            if attr["write_offset"] == offset:
                all_edges.append(edge)

        if len(all_edges) == 0: 
            return None

        else: 
            return self.choose_edge(all_edges)

    def resolve_expr(self, expr):
        resexpr = expr

        # Try resolving symbol name for CALL instructions.
        if expr.operation in [MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA]:
            if expr.dest.operation in [MediumLevelILOperation.MLIL_CONST_PTR, MediumLevelILOperation.MLIL_EXTERN_PTR]:
                symbol = self.bv.get_symbol_at(expr.dest.constant)
                if symbol is not None:
                    resexpr = str(expr).replace(hex(expr.dest.constant), symbol.name, 1)

        return resexpr

    def check_dominators(self, target_expr, free_expr):
        if free_expr.il_basic_block in target_expr.il_basic_block.dominators:
            return True

    def get_last_common_func(self, free_stacktrace, target_stacktrace):
        
        for free_entry in reversed(free_stacktrace):
            for target_entry in reversed(target_stacktrace):
                free_function, free_address = free_entry
                target_function, target_address = target_entry
                
                if free_function == target_function:
                    return free_entry, target_entry

    def get_free_blks(self, log_blks):

        free_blks = list()

        for entry, value in log_blks.items():
            entry_type, expr, expr_block = value
            if entry_type == config.FREE:
                free_blks.append(value)

        return free_blks

    def log_uaf(self, target_expr, free_expr, target_type):

        resexpr = self.resolve_expr(target_expr)
        message = ("[$$$] Potential UAF @ 0x%x %s in function %s || Free @ 0x%x in %s || Allocation @ 0x%x in %s"
            % (target_expr.address, resexpr, target_expr.function.source_function.name, free_expr.address, 
            free_expr.function.source_function.name, self.allocexpr.address, self.allocexpr.function.source_function.name))

        if target_type == config.FREE:
            message = ("[$$$] Potential Double Free @ 0x%x %s in function %s || Free @ 0x%x in %s || Allocation @ 0x%x in %s" 
                % (target_expr.address, resexpr, target_expr.function.source_function.name, free_expr.address, 
                free_expr.function.source_function.name, self.allocexpr.address, self.allocexpr.function.source_function.name))

        # When check for dominators are passed as args, list out expressions that are dominated by free blocks.
        if config.dominators:
            if self.check_dominators(target_expr, free_expr):
                self.log_message(message, logging.CRITICAL)

        else: self.log_message(message, logging.CRITICAL)

    def detect_uaf(self, control_graph, log_blks, allocexpr):

        free_bbs = self.get_free_blks(log_blks)
        
        for free_bb in free_bbs:
            for entry, value in log_blks.items():
                target_type, target_expr, target_stacktrace = value

                _, free_expr, free_stacktrace = free_bb

                common_function = self.get_last_common_func(free_stacktrace, target_stacktrace)
                free_function_entry, target_function_entry = common_function
                free_function_addr, free_addr = free_function_entry
                target_function_addr, target_addr = target_function_entry

                # target_function_addr and free_function_addr are the same, since we find the last common function
                function = self.bv.get_function_at(target_function_addr)
                common_free_expr = function.get_low_level_il_at(free_addr).mlil.ssa_form
                common_target_expr = function.get_low_level_il_at(target_addr).mlil.ssa_form
               
                if common_free_expr == common_target_expr:
                    continue

                if common_free_expr.il_basic_block == common_target_expr.il_basic_block:
                    if common_free_expr.address < common_target_expr.address:
                        self.log_uaf(target_expr, free_expr, target_type)
                
                elif nx.has_path(control_graph[function], common_free_expr.il_basic_block, common_target_expr.il_basic_block):
                    self.log_uaf(target_expr, free_expr, target_type)

