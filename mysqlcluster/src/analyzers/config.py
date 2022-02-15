
function_hooks = dict()
allocator_funcs = dict()

max_depth = 5
stack = list()

# config for marking offset of taint source in a structure.
struct_offset = 0

# config for marking int sizes which could be taint filter during value range analysis. 
AND_RANGE = 0xFFFE
LSR_RANGE = 0
MUL_RANGE = 0

ALLOW_VAL = 0xFFFE

# config for controlling taint filtering during relationship checks. When allow_derived_vars
# is set, variables which are derived from tainted variables are not filtered.
allow_derived_vars = False

taint_marker = [0xDEAD000, 0xDEAD000]

vuln = False
