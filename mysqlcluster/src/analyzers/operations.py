from binaryninja import *

MLIL_CMPS = [MediumLevelILOperation.MLIL_CMP_E, MediumLevelILOperation.MLIL_CMP_NE, MediumLevelILOperation.MLIL_CMP_SLT, MediumLevelILOperation.MLIL_CMP_ULT,
            MediumLevelILOperation.MLIL_CMP_SLE, MediumLevelILOperation.MLIL_CMP_ULE, MediumLevelILOperation.MLIL_CMP_SGE, MediumLevelILOperation.MLIL_CMP_UGE,
            MediumLevelILOperation.MLIL_CMP_SGT, MediumLevelILOperation.MLIL_CMP_UGT]

MLIL_SIGNED_CMPS = [MediumLevelILOperation.MLIL_CMP_SLT, MediumLevelILOperation.MLIL_CMP_SLE, MediumLevelILOperation.MLIL_CMP_SGE, MediumLevelILOperation.MLIL_CMP_SGT]

MLIL_CALLS = [MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA]

MLIL_GET_VARS = [MediumLevelILOperation.MLIL_VAR_SSA, MediumLevelILOperation.MLIL_VAR_SSA_FIELD]

MLIL_SET_VARS = [MediumLevelILOperation.MLIL_SET_VAR_SSA, MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD]
