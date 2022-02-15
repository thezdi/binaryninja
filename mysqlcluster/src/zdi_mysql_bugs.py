# python3 zdi_mysql_bugs.py --function_hooks functions_to_hook.json ndbd.bndb

import sys
import argparse
import logging
from binaryninja import *

import analyzers.config
from analyzers.mliltracer import *

parser = argparse.ArgumentParser()
parser.add_argument("filename", help = "path to binary ninja bndb file")
parser.add_argument("--loglevel", help = "choose logging level for debugging", default = "INFO")
parser.add_argument("--logname", help = "choose log file name", default = "zdi_analysis.log")
parser.add_argument("--function_hooks", help = "provide path to json config")
args = parser.parse_args()

bv = binaryview.BinaryViewType.get_view_of_file(args.filename)

numeric_level = getattr(logging, args.loglevel.upper(), None)
logger = logging.getLogger()
logger.setLevel(numeric_level)

filehandler = logging.FileHandler(args.logname)
filehandler.setLevel(numeric_level)
logger.addHandler(filehandler)

consolehandler = logging.StreamHandler(sys.stdout)
consolehandler.setLevel(numeric_level)
logger.addHandler(consolehandler)

if args.function_hooks is not None:
    with open(args.function_hooks) as func_hooks:
        config.function_hooks = json.load(func_hooks)

# configure start of MySQL Signal Data
config.struct_offset = 0x28

# configure integer ranges to filter FP
config.ALLOW_VAL = 0xFFFE
config.LSR_RANGE = 0x20
config.MUL_RANGE = 0

function_list = dict()
function_list["ZDI-CAN-14501"] = "Dblqh::execDUMP_STATE_ORD"
function_list["ZDI-CAN-14494"] = "Lgman::execute_undo_record"
function_list["ZDI-CAN-14487"] = "Dbspj::execDIH_SCAN_TAB_CONF"
function_list["ZDI-CAN-14500"] = "Dbdih::execCHECKNODEGROUPSREQ"
function_list["ZDI-CAN-14509"] = "Ndbcntr::wait_sp_rep"
function_list["ZDI-CAN-14493"] = "Qmgr::execCM_REGREQ"
function_list["ZDI-CAN-14507"] = "Dbdih::execDIGETNODESREQ"
function_list["ZDI-CAN-14486"] = "Dbtux::execTUX_ADD_ATTRREQ"
function_list["ZDI-CAN-14489"] = "Dbdih::execGET_LATEST_GCI_REQ"
function_list["ZDI-CAN-14497"] = "Dbtup::execTUP_ADD_ATTRREQ"
function_list["ZDI-CAN-14491"] = "Suma::execCONTINUEB"
function_list["ZDI-CAN-14495"] = "Thrman::execDBINFO_SCANREQ"
function_list["ZDI-CAN-14499"] = "Backup::execBACKUP_FRAGMENT_COMPLETE_REP"
function_list["ZDI-CAN-14488"] = "Cmvmi::execSET_LOGLEVELORD"
function_list["ZDI-CAN-14504"] = "Dbdih::execDIVERIFYREQ"
function_list["ZDI-CAN-14506"] = "Thrman::execOVERLOAD_STATUS_REP"
function_list["ZDI-CAN-14505"] = "Dbdih::execCONTINUEB"
function_list["ZDI-CAN-14520"] = "Backup::execDBINFO_SCANREQ"
function_list["ZDI-CAN-15120"] = "Cmvmi::execEVENT_SUBSCRIBE_REQ"
function_list["ZDI-CAN-15121"] = "Dbdict::execLIST_TABLES_CONF"
function_list["ZDI-CAN-15122"] = "Trpman::execOPEN_COMORD"
                
arg_for_index = lambda x: "arg" + str(x + 1)

count = 0
logging.info("Starting analysis...")

# For all functions in binary, check if the parameter is a pointer to Signal

for func in bv.functions:
    for index, param in enumerate(func.parameter_vars):
        if param.type is not None and param.type.type_class == TypeClass.PointerTypeClass:
            if param.type.tokens[0].text == "Signal":
               
                args = dict()
                typeinfo, demangled_name = demangle_gnu3(bv.arch, func.name)
                function_name = get_qualified_name(demangled_name)

                if function_name not in function_list.values():
                    continue
            
                # Set base address as 0 for Signal * argument for propagation
                args[arg_for_index(index)] = 0
                
                # In case a vulnerability is found during tracing, this flag is set to TRUE
                config.vuln = False
                
                func_trace = MLILTracer(bv, func.start)
                func_trace.set_function_args(args)
                func_trace.trace()
                del func_trace
                
                if config.vuln == True:
                    logging.info("[%d] %s" % (count, function_name))
                    count = count + 1
