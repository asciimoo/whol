import re
from urlparse import parse_qsl

FILTER_EXPRESSION='http.request.method == "GET" or http.request.method == "POST"'

# TODO write better triggers
userTrigger = re.compile('^[_]?u(?:ser)?(?:name)?$', re.I | re.U)
passTrigger = re.compile('^[_]?p(?:ass)?(?:w)?(?:ord)?$', re.I | re.U)

def splitString(s, n): 
    return [s[i:i+n] for i in xrange(0, len(s), n)]

def hexStringDecode(s):
    return ''.join(map(unichr, map((lambda y: int(y, 16)), splitString(s, 2))))

def parse(protos):
    ret = []
    host = ''
    method = ''
    uri = ''
    cookie = ''
    data_text_lines = ''
    http_proto = protos[0]
    if len(protos) > 1:
        data_text_lines = protos[1]
    for f in http_proto.firstChild.childNodes:
        if f.attributes['name'].value == 'http.request.method':
            method = f.attributes['show'].value
            continue
        if f.attributes['name'].value == 'http.request.uri':
            method = hexStringDecode(f.attributes['value'].value)
            continue
    for field in http_proto.childNodes[1:]:
        if field.attributes['name'].value == 'http.cookie':
            cookie = hexStringDecode(field.attributes['value'].value)[8:].replace('\r\n', '')
            continue
        if field.attributes['name'].value == 'http.host':
            host = hexStringDecode(field.attributes['value'].value)[6:].replace('\r\n', '')
            continue
        if field.attributes['name'].value == 'http.authorization':
            ret.append(('HTTP_AUTH', field.firstChild.attributes['show'].value))
            continue

    if data_text_lines:
        post_data = hexStringDecode(data_text_lines.firstChild.attributes['value'].value)
        for q in parse_qsl(post_data):
            if userTrigger.match(q[0]):
                ret.append(('HTTP_POST_USER', q[1]))
            if passTrigger.match(q[0]):
                ret.append(('HTTP_POST_PASS', q[1]))

    return ret

