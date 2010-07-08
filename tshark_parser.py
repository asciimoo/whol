#!/usr/bin/env python2.6

import re
import sys

PROTOS = {
        'pop'  : 'Post Office Protocol',                   # POP
        'http' : 'Hypertext Transfer Protocol',            # HTTP
        'ftp'  : 'File Transfer Protocol',                 # FTP
          }


# (short|long) packet description
for spd,lpd in PROTOS.iteritems():
    try:
        exec('from modules import mod_%s' % spd)
    except ImportError, e:
        print "[!] Import Error: %s" % e
    else:
        print "[!] %s module loaded" % spd


class PacketParser:
    def __init__(self, p):
        self.raw = p
        self.src = {}
        self.dst = {}
        # Protocols - e.g. [Protocols in frame: wlan:llc:ip:tcp:http:data-text-lines]
        self.protos = p[9].split(' ')[-1][:-1].split(':')
        # Packet arrival time - e.g. \tArrival Time: Jun 17, 2010 15:41:02.710650000
        self.time = p[1][14:]
        # TODO get MAC of source/destination
        for proto in self.protos:
            if PROTOS.has_key(proto):
                self.iproto = (proto, PROTOS[proto])
                break
        for i,l in enumerate(self.raw):
            if l.startswith('Internet Protocol, '):
                (self.src['ip'], self.dst['ip']) =  [x.split(' ')[0] for x in l[19:].replace('Src: ', '').replace(' Dst: ', '').split(',')]
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


if __name__ == '__main__':
    line = sys.stdin.readline()
    # Frame regexp - e.g. fit to 'Frame 91 (1263 bytes on wire, 1263 bytes captured)\n'
    fs = re.compile(r'^Frame [0-9]+ \([0-9]+ bytes on wire, [0-9]+ bytes captured\)\W$')
    #ps = re.compile(r'^(?:'+')|(:?'.join(PROTOS)+r')\W$')
    packet = []
    while(line):
        if fs.match(line) and len(packet):
            p = PacketParser(packet)
            d = p.getData()
            if len(d):
                print "%s:%d -> %s:%d - %s" % (p.src['ip'], p.src['port'], p.dst['ip'], p.dst['port'], p.time)
                print '\n'.join(["%s %s" % (x[0],x[1]) for x in d])
                print '-'*88
            #print p.getContent()
            packet = []

        packet.append(line.strip().replace(r'\r\n', ''))
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
