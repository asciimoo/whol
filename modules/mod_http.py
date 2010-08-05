#
#                   WHOL MODULE (HTTP)
#
#
# FILTER_EXPRESSION -> pcap filter string to get content from tshark
#
# PROTO_NAME -> {'short_name': 'long_name'}
#
# parse function:
#     parameters:
#       protos  -> minidom object of interested protocols
#
#     return:
#       [ModuleStorage] -> 'value'              : {'type': 'value',}
#                          'complete'           : True/False
#                          'notes'              : "notes"
#                          'relevance'          : 0.0-10.0
#
#               or
#
#       [ModuleStorage] -> 'verification'       : True
#       [ModuleStorage] -> 'value'              : {'type': '',}
#

import re
from urlparse import parse_qsl
from modutils import hexStringDecode, ModuleStorage
import Cookie

FILTER_EXPRESSION='http.request.method == "GET" or http.request.method == "POST" or http.response.code == 200'

PROTO_NAME = {'http' : 'Hypertext Transfer Protocol'}

# TODO write better triggers
userTrigger = re.compile('^[_]?u(?:ser)?(?:name)?$', re.I | re.U)
passTrigger = re.compile('^[_]?p(?:ass)?(?:w)?(?:ord)?$', re.I | re.U)
triggers = (
            (re.compile('^[_]?u(?:ser)?(?:name)?$', re.I | re.U), 'HTTP_POST_USER'),
            (re.compile('^[_]?p(?:ass)?(?:w)?(?:ord)?$', re.I | re.U), 'HTTP_POST_PASS'),
            #(re.compile('sessid', re.I | re.U), 'HTTP_POST_SESS'),
           )


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
            uri = hexStringDecode(f.attributes['value'].value)
            continue
    for field in http_proto.childNodes[1:]:
        if field.attributes['name'].value == 'http.cookie':
            cookie = Cookie.SimpleCookie()
            cookiestr = hexStringDecode(field.attributes['value'].value)[8:].replace('\r\n', '')
            try:
                cookie.load(cookiestr)
            except:
                continue

            for k, v in cookie.iteritems():
                if v.key.find('SESSID') >= 0:
                    ret.append(ModuleStorage(value={'HTTP_COOKIE_SESS': v.value}, complete=True, notes='"%s %s" @ %s' % (method, uri, host), relevance=3))
                    break
            continue
        if field.attributes['name'].value == 'http.host':
            host = hexStringDecode(field.attributes['value'].value)[6:].replace('\r\n', '')
            continue
        if field.attributes['name'].value == 'http.authorization':
            ret.append(ModuleStorage(value={'HTTP_AUTH': field.firstChild.attributes['show'].value}, complete=True, notes='"%s %s" @ %s' % (method, uri, host), relevance=10))
            continue

    if data_text_lines:
        try:
            post_data = hexStringDecode(data_text_lines.firstChild.attributes['value'].value)
        except:
            return ret
        for q in parse_qsl(post_data):
            for trigger in triggers:
                if trigger[0].match(q[0]):
                    ret.append(ModuleStorage(value={trigger[1]: q[1]}, complete=False, notes='%s %s' % (method, uri), relevance=10))

    return ret

