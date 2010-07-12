#!/usr/bin/env python2.6

import re
import sys
from xml.dom.minidom import parseString
from optparse import OptionParser

VERSION = '0.1b'

PROTOS = {
        'pop'  : 'Post Office Protocol',                   # POP
        'http' : 'Hypertext Transfer Protocol',            # HTTP
        'ftp'  : 'File Transfer Protocol',                 # FTP
          }




'''
class PacketParser:
    def __init__(self, p):
        self.raw = p
        self.src = {}
        self.dst = {}
        # Protocols - e.g. [Protocols in frame: wlan:llc:ip:tcp:http:data-text-lines]
        self.protos = p[9].split(' ')[-1][:-1].split(':')
        # Packet arrival time - e.g. \tArrival Time: Jun 17, 2010 15:41:02.710650000
        self.time = p[1][14:]
        self.iproto = None
        # TODO get MAC of source/destination
        for proto in self.protos:
            if PROTOS.has_key(proto):
                self.iproto = (proto, PROTOS[proto])
                break
        if not self.iproto:
            raise NameError("undefined protocols [%s]" % ', '.join(self.protos))

        for i,l in enumerate(self.raw):
            if l.startswith('Internet Protocol, '):
                (self.src['ip'], self.dst['ip']) =  [x.split(' ')[1][1:-1] for x in l[19:].replace('Src: ', '').replace(' Dst: ', '').split(',')]
                continue
            if l.startswith('Transmission Control Protocol, '):
                self.src['port'] = int(self.raw[i+1][13:].split(' ')[1][1:-1])
                # TODO get service name if exists
                self.dst['port'] = int(self.raw[i+2][19:].split(' ')[1][1:-1])
                continue
            if l == self.iproto[1]:
                self.contentIndex = i+1
                break

    def getContent(self):
        return '\n'.join(self.raw[self.contentIndex:])

    def getData(self):
        if not sys.modules.has_key("modules.mod_%s" % self.iproto[0]):
            return {}
        return globals()['mod_%s' % self.iproto[0]].parse(self.raw[self.contentIndex:], self.src, self.dst, self.protos)
'''

class PacketParser:
    def __init__(self, packet_str):
        self.dom = parseString(packet_str).firstChild
        self.protos = []
        self.src = {}
        self.dst = {}
        self.time = ''
        for x in self.dom.childNodes:
            self.protos.append(x.attributes['name'].value)
            if x.attributes['name'].value == 'ip':
                for ia in x.childNodes:
                    if ia.attributes['name'].value == 'ip.src':
                        self.src['ip'] = ia.attributes['show'].value
                    elif ia.attributes['name'].value == 'ip.dst':
                        self.dst['ip'] = ia.attributes['show'].value
                    elif ia.attributes['name'].value == 'ip.src_host':
                        self.src['host'] = ia.attributes['show'].value
                    elif ia.attributes['name'].value == 'ip.dst_host':
                        self.dst['host'] = ia.attributes['show'].value
            elif x.attributes['name'].value == 'tcp':
                for pa in x.childNodes:
                    if pa.attributes['name'].value == 'tcp.srcport':
                        self.src['port'] = int(pa.attributes['show'].value)
                    elif pa.attributes['name'].value == 'tcp.dstport':
                        self.dst['port'] = int(pa.attributes['show'].value)
            elif x.attributes['name'].value == 'geninfo':
                for ga in x.childNodes:
                    if ga.attributes['name'].value == 'timestamp':
                        self.time = ga.attributes['show'].value


    def decode(self):
        ret = []
        for (i, proto) in enumerate(self.dom.childNodes):
            p = proto.attributes['name'].value
            if not sys.modules.has_key("modules.mod_%s" % p):
                continue
            r = []
            r = globals()['mod_%s' % p].parse(self.dom.childNodes[i:])
            if len(r):
                ret.append(r)

        return ret


if __name__ == '__main__':
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage, version=("%%prog %s" % VERSION))
    parser.add_option("-f", "--filter", action='store_true', dest='filter')
    (options, args) = parser.parse_args()
    FILTER_EXP = []
    # (short|long) proto description
    for spd,lpd in PROTOS.iteritems():
        try:
            exec('from modules import mod_%s' % spd)
        except ImportError, e:
            if not options.filter:
                print "[!] Import Error: %s" % e
        else:
            FILTER_EXP.append('('+globals()['mod_%s' % spd].FILTER_EXPRESSION+')')
            if not options.filter:
                print "[!] %s module loaded" % spd
    if options.filter == True:
        filter_str = ' or '.join(FILTER_EXP)
        print filter_str,
        sys.exit(0)
    xml_version = sys.stdin.readline()
    pdml_version = sys.stdin.readline()
    line = sys.stdin.readline()
    # Frame regexp - e.g. fit to 'Frame 91 (1263 bytes on wire, 1263 bytes captured)\n'
    fs = re.compile(r'^Frame [0-9]+ \([0-9]+ bytes on wire, [0-9]+ bytes captured\)\W$')
    #ps = re.compile(r'^(?:'+')|(:?'.join(PROTOS)+r')\W$')
    packet = []
    while(line):
        packet.append(line.strip())
        if line.strip() == '</packet>':
            try:
                p = PacketParser(''.join(packet))
            except NameError, e:
                print e
            else:
                d = p.decode()
                if len(d):
                    print "%s:%d -> %s:%d - %s" % (p.src['ip'], p.src['port'], p.dst['ip'], p.dst['port'], p.time)
                    print d
                    print '-'*88
                #print p.getContent()
            packet = []

        line = sys.stdin.readline()


# NOTES
#
# var as function
#
# Py> def test():
# .... print "Hi there!"
# ....
# Py> var = "test"
# Py> locals()[var]()
#
#
# __import__(name[, globals[, locals[, fromlist[, level]]]])
# 
#
