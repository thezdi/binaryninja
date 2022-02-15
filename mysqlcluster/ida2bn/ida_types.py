# ida64 -A -Sida_types.py -Ltypes.log ndbd.i64

import idaapi
import idautils
import pickle

ida_auto.auto_wait()

entry = dict()

for function in idautils.Functions():
   
    mangled_name =  idc.get_func_name(function)
    function_name = idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_SHORT_DN))

    tif = idaapi.tinfo_t()
    idaapi.get_tinfo(tif, function)
    funcdata = idaapi.func_type_data_t()
    tif.get_func_details(funcdata)

    arglist = list()

    for i in xrange(funcdata.size()):
        arglist.append(idaapi.print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[i].type, '', ''))

    for arg in enumerate(arglist):
        if 'Signal *' in arg:
            entry[function] = [function_name, arglist]
            break

with open('typeinfo.pkl', 'wb') as typeinfo:
    pickle.dump(entry, typeinfo)

ida_pro.qexit(0)
