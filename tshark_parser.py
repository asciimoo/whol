#!/usr/bin/env python

import re
import sys
from datetime import datetime
from hashlib import sha1
from optparse import OptionParser
from os import listdir
from os.path import isfile
from signal import signal, SIGINT
from xml.dom.minidom import parseString


DATA_TYPES = ['TEXT', 'HEX', 'FILE']

VERSION = '0.0.1'

PROTOS = {}

# module content counter
MCC = 0

# incomplete data container - [ModuleStorage]
idc = []
# complete data container - [DataStorage]
cdc = []
# key: ModuleStorage.id, value: idc index to key
hashTable = {}

histData = []

HOST_BLACKLIST = (
    (re.compile('^www-.+.facebook.*$',  re.I | re.U), 'http'),
)


class DataStorage:
    '''Simple data storage'''
    def __init__(self,
                 src='',
                 dst='',
                 dtype=0,
                 desc='',
                 proto='',
                 value=None,
                 verified=False,
                 notes='',
                 src_str='',
                 dst_str='',
                 date=''):
        self.value = value
        # need to switch src-dst in verifications
        if value.verification:
            self.src = dst
            self.dst = src
            self.src_str = src_str
            self.dst_str = dst_str
        else:
            self.src = src
            self.dst = dst
            self.src_str = dst_str
            self.dst_str = src_str
        self.desc = desc
        self.proto = proto
        self.dtype = dtype
        self.date = date
        self.verified = verified
        # verification progress
        self.vp = [len(value.value), 0]
        self.notes = notes
        # TODO date
        self.updateHash()
        self.updateId()

    def updateHash(self):
        self.hash = sha1("{0}{1}{2}{3}".format(self.src,
                                               self.dst,
                                               self.dtype,
                                               self.proto)).hexdigest()

    def updateId(self):
        self.id = sha1("{0}{1}{2}{3}{4}".format(self.src,
                                                self.dst,
                                                self.dtype,
                                                self.proto,
                                                str(self.value))).hexdigest()

    def __unicode__(self):
        return """Destination: {0} -- {2}
{1}
=========================""".format(self.dst_str, unicode(self.value), datetime.now())

    def verify(self):
        if self.verified:
            return
        self.verified = True
        self.value.relevance += 10

    def merge(self, p):
        if self.value.complete and self.verified:
            return False
        if p.verification and not self.verified:
            # use self.vp
            self.verified = True
            self.value.relevance += 10
            if p.notes:
                try:
                    self.value.notes = u'%s - %s' % (p.notes, self.value.notes)
                except:
                    pass
            return True
        self.value.update(p.value)
        self.value.complete = True
        # self.value.notes += ' %s' % p.notes
        self.updateId()
        return True


class PacketParser:
    def __init__(self, packet_str):
        self.dom = parseString(packet_str).firstChild
        self.protos = []
        self.src = {}
        self.src_str = ''
        self.dst = {}
        self.dst_str = ''
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
                        self.src_str = self.src['host']
                    elif ia.attributes['name'].value == 'ip.dst_host':
                        self.dst['host'] = ia.attributes['show'].value
                        self.dst_str = self.dst['host']
            elif x.attributes['name'].value == 'tcp':
                for pa in x.childNodes:
                    if pa.attributes['name'].value == 'tcp.srcport':
                        self.src['port'] = int(pa.attributes['show'].value)
                    elif pa.attributes['name'].value == 'tcp.dstport':
                        self.dst['port'] = int(pa.attributes['show'].value)
            elif x.attributes['name'].value == 'geninfo':
                for ga in x.childNodes:
                    if ga.attributes['name'].value == 'timestamp':
                        self.time = ga.attributes['show'].value.split('.')[0]

        # Stop if src or dst location blacklisted
        # for i in HOST_BLACKLIST:
        #    if (i[0].match(self.dst['host']) or i[0].match(self.src['host']))\
        #        and i[1] in self.protos:
        #        raise Exception('Blacklisted host: %s' % self.dst['host'])

    def decode(self):
        c = 0
        for (i, proto) in enumerate(self.dom.childNodes):
            p = proto.attributes['name'].value
            if "modules.mod_{0}".format(p) not in sys.modules:
                continue
            try:
                r = globals()['mod_%s' % p].parse(self.dom.childNodes[i:], self)
            except Exception, e:
                print '[!] %s module cannot decode packet\n'\
                    '\tError: %s\n' % (p, e)
                print 80*'-'
                continue

            for d in r:
                ds = DataStorage(src=self.src['host'],
                                 dst=self.dst['host'],
                                 proto=p,
                                 value=d,
                                 notes='%s -> %s @ %s' % (self.src_str,
                                                          self.dst['host'],
                                                          self.time),
                                 src_str=self.src['host'],
                                 dst_str=self.dst_str,
                                 date=self.time)
                if d.verification:
                    # if d.complete:
                    #     cdc.append(ds)
                    #     c +=1
                    #     continue
                    for p in reversed(cdc):
                        if p.hash == ds.hash and not p.verified:
                            # TODO check verification
                            cdc.remove(p)
                            p.merge(d)
                            cdc.append(p)
                            c += 1

                            break
                    continue
                if d.complete:
                    if ds.id in histData:
                        continue
                    cdc.append(ds)
                    histData.append(ds.id)
                    c += 1
                else:
                    if ds.hash in hashTable:
                        index = hashTable[ds.hash]
                        if ds.value.value.keys() != idc[index].value.keys():
                            if not ds.merge(idc[index]):
                                continue
                            # idc.pop(index)
                            idc[index] = None
                            hashTable.pop(ds.hash)
                            if ds.id in histData:
                                continue
                            histData.append(ds.id)
                            cdc.append(ds)
                            c += 1
                        else:
                            print 'duplicated item dropped'
                    else:
                        hashTable[ds.hash] = len(idc)
                        idc.append(d)
        return c


def main_loop(relevance_limit):
    global cdc, MCC
    xml_version = sys.stdin.readline()
    pdml_version = sys.stdin.readline()
    line = sys.stdin.readline()
    packet = []
    while(line):
        if line.strip() != '</pdml>' and line != pdml_version and line != xml_version:
            packet.append(line.strip())
            if line.strip() == '</packet>':
                try:
                    p = PacketParser(''.join(packet))
                except Exception:
                    # print e
                    pass
                else:
                    packets = p.decode()
                    if packets > 0:
                        for data in (x for x in cdc[-packets:]
                                     if x.value.relevance > relevance_limit):
                            MCC += 1
                            # print unicode(data)
                            # this loop filters the sensitive data
                            for (k, v) in data.value.value.iteritems():
                                if k.lower().find('user') < 0:
                                    # cut = len(v)-len(v)%3-2
                                    cut = len(v)-3
                                    if cut > 25:
                                        cut = 25
                                    data.value.value[k] = '%s..' % v[:cut]
                            data.value.value = ', '.join(['%s:%s' % (k[0], k[1]) for k in data.value.value.iteritems()])
                            print unicode(data)
                packet = []

        line = sys.stdin.readline()


def destruct(signal, frame):
    print '\nIncomplete packets:'
    print '\n'.join(map(unicode, filter(lambda x: x is not None, idc)))
    print '\nComplete Packets:'
    print '\n'.join(map(unicode, cdc))
    sys.exit(0)

if __name__ == '__main__':
    signal(SIGINT, destruct)
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage, version=("%%prog %s" % VERSION))
    parser.add_option("-f", "--filter", action='store_true', dest='filter')
    parser.add_option("-v", "--verbose", action='store_true', dest='verbose')
    parser.add_option("-r", "--relevance",
                      action='store',
                      type='float',
                      dest='relevance',
                      default=10)
    (options, args) = parser.parse_args()
    FILTER_EXP = []
    # (short|long) proto description
    # TODO read module dir name from command line parameter
    for f in listdir('modules/'):
        if (f.startswith('mod_')
                and f.endswith('.py')
                and isfile('modules/%s' % f)):
            modname = f[:-3]
            try:
                exec('from modules import %s' % modname)
            except ImportError, e:
                if not options.filter:
                    print "[!] Import Error: %s" % e
            else:
                FILTER_EXP.append('('+globals()[modname].FILTER_EXPRESSION+')')
                PROTOS.update(globals()[modname].PROTO_NAME)
                if not options.filter and options.verbose:
                    print "[!] %s module loaded" % modname[4:]
    if not len(PROTOS):
        print "[!] No modules found. exitting.."
        sys.exit(1)
    if options.filter:
        filter_str = ' or '.join(FILTER_EXP)
        print filter_str,
        sys.exit(0)
    if options.verbose:
        print "[!] Relevance filter: %.2f" % options.relevance
    main_loop(options.relevance)
    if options.verbose:
        print '\nIncomplete packets:'
        print '\n'.join(map(unicode, filter(lambda x: x is not None, idc)))
        print '\nComplete Packets:'
        print '\n'.join(map(unicode, cdc))
