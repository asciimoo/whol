#!/usr/bin/env python2.6

from SOAPpy import WSDL, Types

url = 'http://www.editgrid.com/static/EditGrid.wsdl'
wsdl = WSDL.Proxy(url)


SESS_K = ''
WORKB  = 'user/whol/display'
BOOKID = 3805679
SHEETID = 78692657

def updateGrid(src, dst, proto, data, date, notes, sess_str=SESS_K, sheetId=SHEETID):
    return wsdl.appendRow(sess_str, sheetId, (
        Types.structType({'text': '=ROW()-3',   'col': 0, 'sheetId': SHEETID, 'row': -1}),
        Types.structType({'text': '%s' %   src, 'col': 1, 'sheetId': SHEETID, 'row': -1}),
        Types.structType({'text': '%s' %   dst, 'col': 2, 'sheetId': SHEETID, 'row': -1}),
        Types.structType({'text': '%s' % proto, 'col': 3, 'sheetId': SHEETID, 'row': -1}),
        Types.structType({'text': '%s' %  data, 'col': 4, 'sheetId': SHEETID, 'row': -1}),
        Types.structType({'text': '%s' %  date, 'col': 5, 'sheetId': SHEETID, 'row': -1}),
        Types.structType({'text': '%s' % notes, 'col': 6, 'sheetId': SHEETID, 'row': -1}),
    ))

#print wsdl.getAllCellValues(SESS_K, SHEETID)

#print wsdl.getSheetList(SESS_K, BOOKID)

#print wsdl.getBookList(SESS_K)
