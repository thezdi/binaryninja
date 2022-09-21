# https://github.com/joshwatson/emilator

class BNILVisitor(object):

    def __init__(self, **kw):
        super(BNILVisitor, self).__init__()

    def visit(self, expression):

        if expression is None:
            return
        
        method_name = 'visit_{}'.format(expression.operation.name)
        
        if hasattr(self, method_name):
            value = getattr(self, method_name)(expression)
        else:
            value = None
        
        return value
