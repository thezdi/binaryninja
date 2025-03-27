from binaryninja import *
from . import config
import logging
from collections import Counter

class Helpers():

    def has_recursion(self, stacktrace):
        counter = Counter(tuple(entry) for entry in stacktrace)
        return any(count > 1 for count in counter.values())

    def generate_index(self, stacktrace, address):
        stacktrace_tuples = tuple(tuple(function) for function in stacktrace)
        combined = (stacktrace_tuples, address)
        return hash(combined)

    def is_constant(self, var):
        return True if isinstance(var, int) else False

    def get_vars_version(self, ssavar):
       
        # For global variables just return the address as string
        if not isinstance(ssavar, SSAVariable):
            return str(ssavar)

        ssavar_version = ("%s#%s" % (ssavar.var, ssavar.version))

        return ssavar_version

    def get_var_index(self, ssavar):
        # Associate a SSA variable to a function. This helps to uniquely identify a SSA
        # variable within a program.
        ssavar_str = self.get_vars_version(ssavar)
        return str(ssavar_str) + "_" + str(hex(self.function.start))

    def is_stackmem(self, expr):
        return True if expr.value.type == RegisterValueType.StackFrameOffset else False

    def is_globalmem(self, expr):
        return True if expr.value.type == RegisterValueType.ConstantPointerValue else False

    def is_allocmem(self, expr):
        # Check if any of the variable points to allocated memory using the type info
        # associated with the SSA variable.
        for var in expr.vars_read:
            varindex = self.get_var_index(var)
            if varindex in self.vars and self.vars[varindex]["vartype"] == config.MEMALLOC:
                return True

    def log_message(self, message, condition):

        if config.trace_graph: return

        if condition == logging.DEBUG:
            logging.debug(message)
        elif condition == logging.INFO:
            logging.info(message)
        elif condition == logging.CRITICAL:
            logging.critical(message)
        elif condition == logging.WARNING:
            logging.warning(message)
        elif condition == logging.ERROR:
            logging.error(message)
