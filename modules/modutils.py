
def splitString(s, n):
    return [s[i:i+n] for i in xrange(0, len(s), n)]

def hexStringDecode(s):
    return ''.join(map(chr, map((lambda y: int(y, 16)), splitString(s, 2))))

class ModuleStorage:
    "Simple storage class"
    def __init__(self, value=None, complete=False, notes='', relevance=10, verification=False):
        if value is None:
            self.value = {}
        else:
            self.value = value
        self.complete = complete
        self.notes = notes
        self.relevance = relevance
        self.verification = verification

    def __unicode__(self):
        return u'Value: "%s"\n\t%s' % (self.value, self.notes)

    def __str__(self):
        return u'Value: "%s"\n\tRelevance: %f' % (self.value, self.relevance)

    def update(self, value):
        self.value.update(value)

