from modutils import hexStringDecode, ModuleStorage

FILTER_EXPRESSION='pop.request.command == "PASS" or pop.request.command == "USER"'

PROTO_NAME={'pop'  : 'Post Office Protocol'}

def parse(protos):
    # pop.request.parameter
    t = ''
    for p in protos[0].firstChild.childNodes:
        if p.attributes['name'].value == 'pop.request.command':
            t = hexStringDecode(p.attributes['value'].value)
            continue
        if p.attributes['name'].value == 'pop.request.parameter':
            return [ModuleStorage(value={('POP_%s' % t): hexStringDecode(p.attributes['value'].value)}, complete=False, notes=' - ', relevance=10)]

    return []
