from modutils import hexStringDecode, ModuleStorage

FILTER_EXPRESSION='ftp.request == true'

PROTO_NAME={'ftp'  : 'File Transfer Protocol'}

def parse(protos):
    for p in protos[0].childNodes:
        if p.attributes['show'].value.startswith('PASS '):
            return [ModuleStorage(value=[hexStringDecode(p.childNodes[1].attributes['value'].value)], complete=False, dtype='FTP_PASS', notes=' - ', relevance=10)]
        if p.attributes['show'].value.startswith('USER '):
            return [ModuleStorage(value=[hexStringDecode(p.childNodes[1].attributes['value'].value)], complete=False, dtype='FTP_USER', notes=' - ', relevance=10)]
    return []
