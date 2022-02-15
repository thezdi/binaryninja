## Binary Ninja source code for MindShaRE blog on Static Taint Analysis

Run the code as:

`python3 mysql_bugs.py  --function_hooks functions_to_hook.json ndbd.bndb` 

Details of files available in the repository: 
 
`ida2bn` – Has the scripts for porting type information from IDA to Binary Ninja. The `ida_types.py` script exports pickled type information to a file. The `ninja_types.py` script imports the pickled type information and applies it to `ndbd.bndb` database
 
`src` – Has a couple of scripts (`zdi_mysql_bugs.py`, and `mysql_bugs.py`) that invoke the analyzer code. The JSON config file `functions_to_hook.json` has details about functions and parameters meant for static function hooking. While the `mysql_bugs.py` performs a full analysis, `zdi_mysql_bugs.py` analyses only the functions already known to be vulnerable (for testing purposes). 
 
`src/analyzers` – This has all the code for taint propagation, reachability analysis for filtering, variable dependency analysis, logging, etc. The analyzers depend on the python [networkx package][1] for handling graphs. 

[1]: https://networkx.org/