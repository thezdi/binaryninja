from binaryninja import *
import pickle
import argparse
import sys

with open('typeinfo.pkl', 'rb') as typeinfo:
    entries = pickle.load(typeinfo)

parser = argparse.ArgumentParser()
parser.add_argument("filename", help = "path to binary ninja bndb file")
args = parser.parse_args()

bv = binaryview.BinaryViewType.get_view_of_file(args.filename)

signal = types.NamedTypeReference(name = "Signal")
bv.define_user_type("Signal", Type.named_type(signal))
bv.update_analysis_and_wait()

signal_ptr_tinfo = Type.pointer(bv.arch, bv.get_type_by_name("Signal"))

for bn_func in bv.functions:

    bn_args = bn_func.function_type.parameters
    bn_new_args = list()       

    for idx, bn_arg in enumerate(bn_args):
        if bn_arg.type is None:
            bn_arg.type = Type.pointer(bv.arch, Type.void())
            bn_arg.name = "arg" + str(idx)

        elif "Signal" in bn_arg.type.get_string_before_name():
            bn_arg.type = Type.pointer(bv.arch, Type.void())

        bn_new_args.append(bn_arg)
    
    if bn_func.start in entries:

        function_name, ida_args = entries[bn_func.start]

        for idx, ida_arg in enumerate(ida_args):
            if "Signal *" in ida_arg and idx < len(bn_new_args):
                bn_new_args[idx].type = signal_ptr_tinfo

    bn_args_types = list()
    
    for vars, params in zip(bn_new_args, bn_args):
        bn_args_types.append(FunctionParameter(vars.type, params.name, params.location))

    func_tinfo = Type.function(bn_func.return_type, bn_args_types, bn_func.calling_convention, bn_func.has_variable_arguments, bn_func.stack_adjustment)
    bn_func.function_type = func_tinfo
    
bv.update_analysis_and_wait()
bv.save_auto_snapshot()
