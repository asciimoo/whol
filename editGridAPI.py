#!/usr/bin/env python2.6

from SOAPpy import WSDL, Types

url = 'http://www.editgrid.com/static/EditGrid.wsdl'
wsdl = WSDL.Proxy(url)


SESS_K = ''
WORKB  = 'user/whol/display'
BOOKID = 3805679
SHEETID = 78692657

def updateGrid(index, src, dst, proto, data, date, notes, sess_str=SESS_K, sheetId=SHEETID):
    wsdl.insertRow(sess_str, sheetId, 6, 1)
    return wsdl.setCellValues(sess_str, sheetId, (
        Types.structType({'text': '%d' % index, 'col': 0, 'sheetId': SHEETID, 'row': 6}),
        Types.structType({'text': '%s' %   src, 'col': 1, 'sheetId': SHEETID, 'row': 6}),
        Types.structType({'text': '%s' %   dst, 'col': 2, 'sheetId': SHEETID, 'row': 6}),
        Types.structType({'text': '%s' %  data, 'col': 3, 'sheetId': SHEETID, 'row': 6}),
        Types.structType({'text': '%s' % proto, 'col': 4, 'sheetId': SHEETID, 'row': 6}),
        Types.structType({'text': '%s' %  date, 'col': 5, 'sheetId': SHEETID, 'row': 6}),
        Types.structType({'text': '%s' % notes, 'col': 6, 'sheetId': SHEETID, 'row': 6}),
    ))

#updateGrid(2, '192.168.1.111', 'freemail.hu', 'http', 'user: asdf, pass:qwer', '2010.08.26 15:12:12', 'no notes')

#print wsdl.getAllCellValues(SESS_K, SHEETID)

#print wsdl.getSheetList(SESS_K, BOOKID)

#print wsdl.getBookList(SESS_K)
