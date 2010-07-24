

def splitString(s, n): 
    return [s[i:i+n] for i in xrange(0, len(s), n)]

def hexStringDecode(s):
    return ''.join(map(unichr, map((lambda y: int(y, 16)), splitString(s, 2))))

class ModuleStorage:
    "simple storage class"
    def __init__(self, value=[''], dtype='', complete=False, notes='', relevance=10):
        self.value      = value
        self.complete   = complete
        self.dtype      = dtype
        self.notes      = notes
        self.relevance  = relevance

    def __unicode__(self):
        return u'Value: "%s", Complete: %s, Notes: %s, Relevance: %f, Type: %s' % (self.value, str(self.complete), self.notes, self.relevance, self.dtype)
