from modutils import hexStringDecode, ModuleStorage

FILTER_EXPRESSION='ftp'

PROTO_NAME={'ftp'  : 'File Transfer Protocol'}

def parse(protos):
    if protos[0].childNodes[2].attributes['show'].value.startswith('230 OK'):
        return [ModuleStorage(value={'FTP_VERIF': ''}, complete=False, notes=' - ', relevance=10, verification=True)]
    for p in protos[0].childNodes:
        if p.attributes['show'].value.startswith('PASS '):
            return [ModuleStorage(value={'pass': hexStringDecode(p.childNodes[1].attributes['value'].value)}, complete=False, notes=' - ', relevance=10)]
        if p.attributes['show'].value.startswith('USER '):
            return [ModuleStorage(value={'user': hexStringDecode(p.childNodes[1].attributes['value'].value)}, complete=False, notes=' - ', relevance=10)]
    return []
