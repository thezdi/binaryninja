from binaryninja import *
from . import config
import networkx as nx
import logging

class Reachability():

    def check_definition_by_region(self, var, parent_def_blk, child_def_blk):
        region_blocks = self.var_def_uses[var]["region_blocks"]

        if child_def_blk not in region_blocks:
            return True

    def get_reachable_blocks_by_region(self, var_def, var, target_blocks):
        
        reachable_blocks = set()
        def_blk = var_def.il_basic_block

        regions_blocks = self.var_def_uses[var]["region_blocks"]

        for blk in target_blocks:
            if blk not in regions_blocks:
                reachable_blocks.add(blk)

        return reachable_blocks

    def check_definition_by_dominance(self, var, parent_def_blk, child_def_blk):
        
        constraint_blocks = self.var_def_uses[var]["constraint_blocks"]

        if not any(x in child_def_blk.strict_dominators for x in constraint_blocks):
            return True

    def get_reachable_blocks_by_dominance(self, var_def, var, target_blocks):

        reachable_blocks = set()
        def_blk = var_def.il_basic_block

        constraint_blocks = self.var_def_uses[var]["constraint_blocks"]

        for blk in target_blocks:
            if not any(x in blk.strict_dominators for x in constraint_blocks):
                reachable_blocks.add(blk)

        return reachable_blocks

    def get_reachable_blocks_by_path(self, var_def, var, target_blocks):

        reachable_blocks = set()
        def_blk = var_def.il_basic_block

        subgraph = self.var_def_uses[var]["subgraph"]

        for blk in target_blocks:
            if nx.has_path(subgraph, def_blk, blk):
                reachable_blocks.add(blk)

        return reachable_blocks

    def check_definition_by_path(self, var, parent_def_blk, child_def_blk):
        subgraph = self.var_def_uses[var]["subgraph"]

        return nx.has_path(subgraph, parent_def_blk, child_def_blk)

    def get_reachable_blocks(self, var_def, var, target_blocks):
        return self.get_reachable_blocks_by_path(var_def, var, target_blocks)

    def check_definition(self, var, parent_def_blk, child_def_blk):
        return self.check_definition_by_path(var, parent_def_blk, child_def_blk)

    def get_region_blocks(self, graph, var):

        constraint_blocks = self.var_def_uses[var]["constraint_blocks"]
        region_blocks = set()

        for constraint_block in constraint_blocks:

            child_blocks = set(nx.descendants(self.graph, constraint_block))
            reachable_blocks = set()

            for child_blk in child_blocks:
                parents = list(self.graph.predecessors(child_blk))

                if constraint_block in parents:
                    parents.remove(constraint_block)

                if any(parent not in child_blocks for parent in parents):
                    reachable_blocks.add(child_blk)

                    subchilds = nx.descendants(self.graph, child_blk)
                    reachable_blocks.update(set(subchilds))

            region_blocks.update(child_blocks - reachable_blocks)

        return region_blocks 

    def get_function_graph(self, function):

        graph = nx.DiGraph()

        for blk in function.mlil.ssa_form.basic_blocks:
            for outgoing_edge in blk.outgoing_edges:
                graph.add_edge(blk, outgoing_edge.target)

            for incoming_edge in blk.incoming_edges:
                graph.add_edge(incoming_edge.source, blk)

        return graph

    def get_constrained_subgraph(self, constraint_blocks):

        subgraph = self.graph.copy()

        for constraint_block in constraint_blocks:
            if len(constraint_block.outgoing_edges) != 2:
                continue

            for outgoing_edge in constraint_block.outgoing_edges:
                subgraph.remove_edge(constraint_block, outgoing_edge.target)

        return subgraph

