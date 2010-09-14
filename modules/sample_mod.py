#
#                   WHOL MODULE
#
#
# FILTER_EXPRESSION -> pcap filter string to get content from tshark
#
# PROTO_NAME -> {'short_name': 'long_name'}
#
# parse function:
#     parameters:
#       protos  -> minidom object of interested protocols
#       packet  -> the full packet object from tshark_parser.py
#
#     return:
#       [] or
#       [ModuleStorage] -> 'value'       : ["values"]
#                          'dtype'       : "type"
#                          'complete'    : True/False
#                          'notes'       : "notes"
#                          'relevance'   : 0.0-10.0

from modutils import ModuleStorage

FILTER_EXPRESSION='tshark display filter - see http://www.wireshark.org/docs/dfref/ for full list'

PROTO_NAME={'proto'  : 'Long name'}

def parse(proto, full_packet):
    return [ModuleStorage()]


