## Binary Ninja source code for MindShaRE blog on Use-After-Free Analysis

Below are some examples to run the code:

```
$ python3 analyze_allocators.py --check_type_size --allocator_funcs jas_allocator_functions.json --logname analysis.log mif_cod.o.bndb

$ python3 analyze_allocators.py --find_deallocators --check_type_size --allocator_funcs giflib.json --logname analysis.log gifcolor.o.bndb

$ python3 analyze_allocators.py --find_deallocators --check_type_size --allocator_funcs gnome-nettool.json --logname analysis.log gnome-nettool.bndb

$ python3 analyze_allocators.py --find_deallocators --check_type_size --allocator_funcs slp.json --filter_function SLPDProcessMessage --logname analysis.log slpd.bndb


$ python3 analyze_allocators.py --help
usage: analyze_allocators.py [-h] [--loglevel LOGLEVEL] [--logname LOGNAME] [--propagate_reads] [--check_type_size] [--function_hooks FUNCTION_HOOKS] --allocator_funcs ALLOCATOR_FUNCS
                             [--dump_data_graph] [--dominators] [--filter_function FILTER_FUNCTION] [--find_deallocators] [--recursion_limit [RECURSION_LIMIT]]
                             filename

positional arguments:
  filename              path to binary ninja bndb file

options:
  -h, --help            show this help message and exit
  --loglevel LOGLEVEL   choose logging level for debugging
  --logname LOGNAME     choose log file name
  --propagate_reads     propagate reads from allocated memory
  --check_type_size     propagate pointers by checking SSA variable type
  --function_hooks FUNCTION_HOOKS
                        provide path to json config
  --allocator_funcs ALLOCATOR_FUNCS
                        provide path to json config
  --dump_data_graph     enable dumping data graph for debugging
  --dominators          enable dominator based checks
  --filter_function FILTER_FUNCTION
                        provide a specific function name to track
  --find_deallocators   enumerate possible wrappers for deallocators
  --recursion_limit [RECURSION_LIMIT]
                        increase recursion limit when needed
```

Some sample json files are found in `jsons` directory. The analyzers depend on the python [networkx package][1] for handling graphs. 

[1]: https://networkx.org/


