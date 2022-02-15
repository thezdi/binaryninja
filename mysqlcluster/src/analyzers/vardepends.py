from binaryninja import *
from . import operations
import networkx as nx
import logging

class VarDepends(): 

    def build_ssavar_dependency_graph(self):

        vargraph = nx.DiGraph()

        for var in self.tainted_vars:
        
            vargraph.add_node(var)

            var_def = self.function.mlil.ssa_form.get_ssa_var_definition(var)
            
            # NOTE: Tainted SSA variable is coming as a function args.
            if var_def is None:
                continue

            if var_def.operation in operations.MLIL_SET_VARS:

                # NOTE: Tainted SSA variable is coming from a tainted memory region.
                if var_def.src.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
                    continue

                for var_read in set(var_def.src.vars_read):
                    if var_read in self.tainted_vars:
                        vargraph.add_edge(var_read, var)

            elif var_def.operation == MediumLevelILOperation.MLIL_VAR_PHI:

                for var_read in var_def.src:
                    if var_read in self.tainted_vars and var_read != var_def.dest:
                        vargraph.add_edge(var_read, var)

        self.vargraph = vargraph

        self.process_ssavar_dependency(vargraph)

    def process_ssavar_dependency(self, vargraph):

        for var in self.tainted_vars:
            root_vars = dict()
            ancestors = nx.ancestors(vargraph, var)

            if len(ancestors) == 0:
                root_vars[var] = self.var_def_uses[var]["sink_blocks"]
                self.var_def_uses[var]["root_vars"] = root_vars
                continue

            roots = self.get_roots(ancestors)
            for root in roots:
                root_vars[root] = self.var_def_uses[var]["sink_blocks"]
          
            self.var_def_uses[var]["root_vars"] = root_vars

    def get_roots(self, ancestors):

        roots = list()

        for ancestor in ancestors:
            if len(self.vargraph.in_edges(ancestor)) == 0:
                roots.append(ancestor)

        return roots

    def get_child_vars(self, var):
        return nx.descendants(self.vargraph, var)

    def get_parent_vars(self, var):
        return nx.ancestors(self.vargraph, var)
