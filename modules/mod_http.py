# -*- coding: utf-8 -*-
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

FILTER_EXPRESSION='http.request.method == "GET" or http.request.method == "POST" or (http.response.code == 200 and http.content_type contains "html")'

PROTO_NAME = {'http' : 'Hypertext Transfer Protocol'}

# TODO write better triggers
triggers = (
            (re.compile('^[_]?u(?:ser)?(?:name)?$', re.I | re.U), 'username'),
            (re.compile('^[_]?p(?:ass)?(?:w)?(?:ord)?$', re.I | re.U), 'password'),
            #(re.compile('sessid', re.I | re.U), 'HTTP_POST_SESS'),
           )

verif_trigg = re.compile(u'\W*(?:logout|sign out|kijelentkezés)\W*', re.I | re.U | re.M)

# Thx to w3af (collectCookies plugin) for the list of session cookies
SESSION_DB = ( 
        ('st8id','Teros web application firewall'), # Web application firewalls
        ('ASINFO','F5 TrafficShield'),              # Web application firewalls
        ('NCI__SessionId','Netcontinuum'),          # Web application firewalls
        ('$OC4J_','Oracle container for java'),     # Oracle
        ('JSESSIONID','Jakarta Tomcat / Apache'),   # Java
        ('JServSessionIdroot','Apache JServ'),      # Java
        ('ASPSESSIONID','ASP'),                     # ASP
        ('ASP.NET_SessionId','ASP.NET'),            # ASP
        ('PHPSESSID','PHP'),                        # PHP
        ('sap-usercontext=sap-language','SAP'),     # SAP
        ('WebLogicSession','BEA Logic'),            # Others..
        ('SaneID','Sane NetTracker'),
        ('ssuid','Vignette'),
        ('vgnvisitor','Vignette'),
        ('SESSION_ID','IBM Net.Commerce'),
        ('NSES40Session','Netscape Enterprise Server'),
        ('iPlanetUserId','iPlanet'),
        ('RMID','RealMedia OpenADStream'),
        ('cftoken','Coldfusion'),
        ('PORTAL-PSJSESSIONID','PeopleSoft'),
        ('WEBTRENDS_ID','WebTrends'),
        ('sesessionid','IBM WebSphere'),
        ('CGISESSID','Perl CGI::Session'),
        ('GX_SESSION_ID','GeneXus'),
        ('WC_SESSION_ESTABLISHED','WSStore'),
    )

def parse(protos):
    if protos[0].firstChild.attributes['name'].value == 'data':
        # print "[!] DATA?!"
        return []
    ret = []
    host = ''
    method = ''
    uri = ''
    cookie = ''
    data_text_lines = ''
    http_proto = protos[0]
    try:
        if http_proto.firstChild.childNodes[2].attributes['name'].value == 'http.response.code':
            if protos[1].attributes['name'].value == 'data-text-lines':
                # TODO write to file?!
                full_response_content = ''.join([hexStringDecode(x.attributes['value'].value) for x in protos[1].childNodes])
                if verif_trigg.search(full_response_content):
                    # HTTP verification found!
                    ret.append(ModuleStorage(value={'HTTP_POST_VERIF': ''}, complete=False, notes=' - ', relevance=10, verification=True))

            # else:
            #    print '\n\n'.join([x.toprettyxml() for x in protos])
            # parse the response for validations
            return ret
    except:
        #print '\n\n'.join([x.toprettyxml() for x in protos])
        pass
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
                if len(ret):
                    break
                for s,d in SESSION_DB:
                    if s == k:
                        ret.append(ModuleStorage(value={('%s session' % d): v.value}, complete=True, notes='"%s %s" @ %s' % (method, uri, host), relevance=3))
                        break
            continue
        if field.attributes['name'].value == 'http.host':
            host = hexStringDecode(field.attributes['value'].value)[6:].replace('\r\n', '')
            continue
        if field.attributes['name'].value == 'http.authorization':
            ret.append(ModuleStorage(value={'http basic auth': field.firstChild.attributes['show'].value}, complete=True, notes='"%s %s" @ %s' % (method, uri, host), relevance=10))
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

    
