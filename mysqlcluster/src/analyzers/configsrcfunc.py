from . import config

# Rewrite this function, when an offset + size value should be considered tainted.
# An valid offset for taint could be from a base offset of a structure or a range
# of offsets within a structure or a particular DWORD, QWORD etc.

def check_src(offset, size):
    if offset >= config.struct_offset:
        return True
