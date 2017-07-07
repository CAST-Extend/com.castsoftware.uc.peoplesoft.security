'''
Created on Jun 16, 2017

@author: JGD
'''

import re

def testIt():
    line = '   SQLExec("select %DateTimeDiff(%DateTimeIn(" | Quote(String(&fromdatetime)) | "), %DateTimeIn(" | Quote(String(&todatetime)) | ")) from psoptions", &minutes);'
    #line = '   &SQL = CreateSQL("select d.parmname,nvl(rtrim(i.parmvalue), d.parmvalue) from PSDDLDEFPARMS d, PSIDXDDLPARM i WHERE d.STATEMENT_TYPE = 2 AND d.PLATFORMID = :1 AND SIZING_SET = :2 and i.recname(+)=:3 and i.indexid(+)=:4 and i.platformid(+)=d.PLATFORMID  and i.SIZINGSET(+)=d.SIZING_SET and i.parmname(+)=d.parmname", &DB_PLATFORM_ID, 0, &sRecordName, &EF_in_sIndexId);'
    #line = 'SQLExec("drop index " | &EF_lsPKindexName);'
    #line = 'SQLExec("UPDATE %TABLE(" | &recordName | ") SET " | &sysIds [&i] [1] | " = LI_STG_RECNUM + " | Value(&srcMap.getSysIdOffset(&sysIds [&i] [2] )));'
    
    searchObj1 = re.findall('\|[ \t]*"', line, re.I)
    searchObj2 = re.findall( '\|[ \t]*Quote\(', line, re.I)
    
    print(len(searchObj1) == len(searchObj2))

testIt()