import logging

bug_index = 0

def get_var_for_arg(expr, arg):

    params = expr.params
    argno = lambda _arg: int(_arg.split("arg").pop())

    if argno(arg) < len(params):
        param_value = params[argno(arg)]
        return param_value
    else:
        return None

def get_leaked_bytes(stores, source, copy_size):
    memory_access = dict()
    leaked_bytes = list()

    # create byte map of accessed memory region
    for offset, store_size in stores.items():
        for curr_offset in range(offset, offset + store_size):
            memory_access[curr_offset] = True

    # check the offsets copied against the mapping
    for curr_offset in range(source, source + copy_size):
        if curr_offset not in memory_access:
            leaked_bytes.append(curr_offset)

    return leaked_bytes

def get_uninitialized_offsets(stores, source, copy_size):
    pass

def log_leak_info(leaked_offsets, size, address, name):

    global bug_index
    leakedbytes = len(leaked_offsets)

    if leakedbytes > 0 and size > 0:
        bug_index += 1
        logging.info("[%d] Possible leak of %d bytes when copying %d bytes @ 0x%lx (%s)"
                            % (bug_index, leakedbytes, size, address, name))

