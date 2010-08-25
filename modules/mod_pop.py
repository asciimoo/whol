from modutils import hexStringDecode, ModuleStorage

FILTER_EXPRESSION='pop.request.command == "PASS" or pop.request.command == "USER" or pop.response'

PROTO_NAME={'pop'  : 'Post Office Protocol'}

def parse(protos):
    # pop.request.parameter
    t = ''
    if protos[0].firstChild.attributes['name'].value == 'pop.response':
        if protos[0].firstChild.attributes['showname'].value.startswith('+OK logged in.'):
            return [ModuleStorage(value={'POP_VERIF': ''}, complete=False, notes=' - ', relevance=10, verification=True)]

    for p in protos[0].firstChild.childNodes:
        if p.attributes['name'].value == 'pop.request.command':
            t = hexStringDecode(p.attributes['value'].value)
            continue
        if p.attributes['name'].value == 'pop.request.parameter':
            return [ModuleStorage(value={('%s' % t).lower(): hexStringDecode(p.attributes['value'].value)}, complete=False, notes=' - ', relevance=10)]

    return []
