from binaryninja import *
from . import config

def get_llil_basic_block(function, llil):

    for bb in function.llil.ssa_form.basic_blocks:
        if llil.instr_index >= bb.start and llil.instr_index < bb.end:
            return bb

def get_llil_dominators(function, llil):
    bb = get_llil_basic_block(function, llil)
    return bb.dominators

def get_mlil_basic_block(function, mlil):

    for bb in function.mlil.ssa_form.basic_blocks:
        if mlil.instr_index >= bb.start and mlil.instr_index < bb.end:
            return bb

def get_mlil_dominators(function, mlil):
    bb = get_mlil_basic_block(function, mlil)
    return bb.dominators

def get_mlilfunc_post_dominators(function):
    entry_block = function.mlil.ssa_form.basic_blocks[0]
    return [entry_block] + entry_block.post_dominators

def is_dominator(function, dominators, expr):

    if config.check_dominators:

        if isinstance(expr, MediumLevelILInstruction):
            bb = get_mlil_basic_block(function, expr)
        elif isinstance(expr, LowLevelILInstruction):
            bb = get_llil_basic_block(function, expr)

        if bb in dominators:
            return True
        else: return False
        
    else: return True
