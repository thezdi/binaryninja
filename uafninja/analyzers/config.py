import itertools

function_hooks = dict()
allocator_funcs = dict()
all_dealloc_funcs = list()

max_depth = 5
stacktrace = list()

dyncounter = itertools.count(0)

MEMALLOC = "ALLOC"
MEMALLOC_COLOR = "#162347"
DYNAMIC = "DYNAMIC"
STACK = "STACK"
GLOBAL = "GLOBAL"


check_type_size = False
propagate_reads = False
dealloc_func = None
alloc_func = None

# operations
READ = "READ"
WRITE = "WRITE"
CALL = "CALL"
FREE = "FREE"

trace_graph = False
