from modutils import hexStringDecode, ModuleStorage

FILTER_EXPRESSION='ftp'

PROTO_NAME={'ftp'  : 'File Transfer Protocol'}

def parse(protos):
    for p in protos[0].childNodes:
        if p.attributes['show'].value.startswith('PASS '):
            return [ModuleStorage(value={'FTP_PASS': hexStringDecode(p.childNodes[1].attributes['value'].value)}, complete=False, notes=' - ', relevance=10)]
        if p.attributes['show'].value.startswith('USER '):
            return [ModuleStorage(value={'FTP_USER': hexStringDecode(p.childNodes[1].attributes['value'].value)}, complete=False, notes=' - ', relevance=10)]
    return []
