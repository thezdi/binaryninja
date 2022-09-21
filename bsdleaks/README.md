## Binary Ninja Code for Finding Uninitialized Memory Disclosures

There are couple of scripts in the analyser - `analyze_stack_src.py` and `analyze_undetermined_src.py`. The `analyze_stack_src.py` is used to analyse sink function with known size and stack offset values. The `analyze_undetermined_src.py` is used to analyse sink function with known size and unknown source pointer. Since the source pointer could be from a heap allocator, provide a json configuration with a list of allocator functions as an argument. Dominator analysis is experimental, therefore enable it using an optional argument when needed:

```
python3 analyze_stack_src.py --function_hooks functions_to_hook.json kernel.bndb

python3 analyze_stack_src.py --dominators --function_hooks functions_to_hook.json kernel.bndb

python3 analyze_undetermined_src.py --function_hooks functions_to_hook.json --allocator_funcs allocator_functions.json kernel.bndb

python3 analyze_undetermined_src.py --dominators --function_hooks functions_to_hook.json --allocator_funcs allocator_functions.json kernel.bndb
```

Details on using the files available in repository:

`stacktracer.py` - Handles stack memory logs in the local function scope    
`mliltracer.py` - Handles memory logs during inter procedure analysis or when the memory source is not from stack region    
`dominators.py` - Has helpers for performing analysis using dominance relationship     
`searchvar.py` - Handles tracking an undetermined source pointer to a memory source e.g. allocator function     

The `analyze_stack_src.py` and `analyze_undetermined_src.py` can be modified to work against other targets of interest. Just update the sink function and parameters involving source memory and size to copy.

```
analyze_function(bv, "copyout", "arg0", "arg2")
```
