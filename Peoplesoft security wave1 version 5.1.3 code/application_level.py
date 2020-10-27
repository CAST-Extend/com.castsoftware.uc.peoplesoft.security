import cast_upgrade_1_6_5 # @UnusedImport
from cast.application import ApplicationLevelExtension, Bookmark
from cast.application import open_source_file # @UnusedImport @UnresolvedImport
import logging
import traceback
import re

def is_not_commented_out(line):
    searchObj = re.search( '^[ \t]*(rem[ \t]+|/\*)', line, re.I)
    return not searchObj

def quote_is_missing(line):
    searchObj1 = re.findall('\|[ \t]*"', line, re.I)
    searchObj2 = re.findall( '\|[ \t]*Quote\(', line, re.I)
    
    return len(searchObj1) != len(searchObj2)

class PsftSecuExtension(ApplicationLevelExtension):

    #initialization of variables
    nbSrcFileScanned = 0
    nbObjectInViolationForSQLExec = 0
    nbObjectInViolationForXSS = 0
    nbObjectInViolationAvoidFile = 0
    nbObjectInViolationAvoidOSCommand = 0
    nbObjectInViolationLogForging = 0
    
    sql_patterns = ['SQLExec(', 'CreateSQL(', '.Fill(', '.FillAppend(', '.Select(', '.SelectNew(']
    file_patterns=['FileExists(', 'GetFile(', 'FindFiles(']
    oscmdpatterns=['Exec(', 'WinExec(', 'RemoteCall(']
    logforgingpatterns=['WriteToLog(']    
    skippattern=['SQLExec(', 'SQL_Exec(']
     
           
    #GetField(xxx).Value
    input_patterns = ['%Request','GetHTMLText(', 'GetParameter(', 'GetParameterNames(', 'GetParameterValues(', 'GetContentBody(', 'GetField(']
    output_patterns = ['%Response'] #%Response.Write( %Response.WriteLine(
    
    def scan_file(self, application, _file):
        #logging.debug("INIT scan_file : file > " +str(_file))
        #initialization
        isInViolationForSQL = False
        isInViolationForXSS = False
        isInViolationForAvoidFile = False
        isInViolationForAvoidOSCommand = False
        isInViolationForLogForging = False
        

        input_lines = []
        
        lineNb = 0
        
        try:
        
            with getfilebyencode(_file.get_path()) as src_file:
                for line in src_file:
                        lineNb +=1
                        # TODO : find input + find target + no sani == violation
                        # TEMP : direct violation on SQL target
                        if is_not_commented_out(line):
                            for pattern in self.sql_patterns:
                                if (pattern in line):
                                    if ('|' in line) & quote_is_missing(line):
                                        isInViolationForSQL = True
                                        # find the object behind this line of code... see MRO email 'functions' on ven. 12/05/2017 17:00 ...
                                        obj = _file.find_most_specific_object(lineNb, 1)  # internal API used under the hood by ReferenceFinder API.
                                        SQLTargetBookmark = Bookmark(_file, lineNb, 1, lineNb, -1)
                                        # TODO : do I need to check if same object will have multiple violations ?
                                        # answer : no, the property is declared as sum, so it should work fine.
                                        obj.save_violation('Psft_Security_CustomMetrics.Pcode_SQL_Injection', SQLTargetBookmark)
                        
                            #Detect input patterns and store the lineNb in the input_lines array
                            for pattern in self.input_patterns:
                                if pattern in line:
                                    input_lines.append(lineNb)
                                    break                
                            
                            #Detect output patterns
                            for pattern in self.output_patterns:
                                if pattern in line:
                                    output_object = _file.find_most_specific_object(lineNb, 1)
                                    output_bookmark = Bookmark(_file, lineNb, 1, lineNb, -1)
                                    
                                    #TODO Add Property for LWI in all cases
                                    
                                    
                                    #if object also has input patterns detected then it's a potential XSS
                                    foundOne = False
                                    for lNb in input_lines:
                                        input_object = _file.find_most_specific_object(lNb, 1)
                                        if input_object == output_object:
                                            if not foundOne:
                                                foundOne = True
                                                isInViolationForXSS = True
                                                output_object.save_violation('Psft_Security_CustomMetrics.Pcode_XSS_Injection', output_bookmark)
                                            input_bookmark  = Bookmark(_file, lNb, 1, lNb, -1)
                                            input_object.save_violation('Psft_Security_CustomMetrics.Pcode_XSS_Injection', input_bookmark)
                            
                            for pattern in self.file_patterns:
                                if (pattern in line):
                                        isInViolationForAvoidFile = True
                                        # find the object behind this line of code... see MRO email 'functions' on ven. 12/05/2017 17:00 ...
                                        obj = _file.find_most_specific_object(lineNb, 1)  # internal API used under the hood by ReferenceFinder API.
                                        AvoidFileTargetBookmark = Bookmark(_file, lineNb, 1, lineNb, -1)
                                        obj.save_violation('Psft_Security_CustomMetrics.Pcode_CWE73violation', AvoidFileTargetBookmark )
                                        
                            for pattern in self.oscmdpatterns:
                                if (pattern in line):
                                    if not checkskippattern(self, line):
                                        isInViolationForAvoidOSCommand = True
                                        # find the object behind this line of code... see MRO email 'functions' on ven. 12/05/2017 17:00 ...
                                        obj = _file.find_most_specific_object(lineNb, 1)  # internal API used under the hood by ReferenceFinder API.
                                        AvoidOSCommandTargetBookmark = Bookmark(_file, lineNb, 1, lineNb, -1)
                                        obj.save_violation('Psft_Security_CustomMetrics.Pcode_CWE78violation', AvoidOSCommandTargetBookmark )
                            
                            for pattern in self.logforgingpatterns:
                                if (pattern in line):
                                        isInViolationForLogForging = True
                                        # find the object behind this line of code... see MRO email 'functions' on ven. 12/05/2017 17:00 ...
                                        obj = _file.find_most_specific_object(lineNb, 1)  # internal API used under the hood by ReferenceFinder API.
                                        LogForgingTargetBookmark = Bookmark(_file, lineNb, 1, lineNb, -1)
                                        obj.save_violation('Psft_Security_CustomMetrics.Pcode_CWE117violation', LogForgingTargetBookmark )
                                          
                # reporting the violations for statistics / logging purpose - outside of the loop
                if isInViolationForSQL == True:
                    self.nbObjectInViolationForSQLExec += 1
                if isInViolationForXSS == True:
                    self.nbObjectInViolationForXSS += 1
                if isInViolationForAvoidFile == True:
                    self.nbObjectInViolationAvoidFile += 1
                if isInViolationForAvoidOSCommand == True:
                    self.nbObjectInViolationAvoidOSCommand += 1
                if isInViolationForLogForging == True:
                    self.nbObjectInViolationLogForging += 1
           
        except Exception as e:
                logging.warning('Internal issue: ' + _file.get_path() + ' could not be parsed.')
                logging.warning(str(traceback.format_exc()))
                return None

    def end_application(self, application):
         
        logging.debug("Running code at the end of an application")
        
        #declare ownership for all diags (this call also performs the required init cleaning)
        application.declare_property_ownership('Psft_Security_CustomMetrics.Pcode_SQL_Injection',['PSoft_Object'])
        application.declare_property_ownership('Psft_Security_CustomMetrics.Pcode_XSS_Injection',['PSoft_Object'])
        application.declare_property_ownership('Psft_Security_CustomMetrics.Pcode_CWE73violation',['PSoft_Object'])
        application.declare_property_ownership('Psft_Security_CustomMetrics.Pcode_CWE78violation',['PSoft_Object'])
        application.declare_property_ownership('Psft_Security_CustomMetrics.Pcode_CWE117violation',['PSoft_Object'])
        
        # list all files saved by PeopleSoft Analyzer
        #files = application.get_files(['PSoft_Object'])
        files = application.get_files()
         
        #looping through Psft objects
        unWantedFolders = ['SQL0', 'SQLAEAction', 'SQLRecord']  # 3 folders containing templates and SQL code, not PeopleCode : exclude from scanning
        for o in files:
            # check if file is analyzed source code, or if it generated (Unknown)
            if not o.get_path():
                continue
            # check if file is a program , skip the copybooks (for the moment at least)
            if not o.get_path().endswith('.src'):
                continue
            # eliminate .src files from unWantedFolders
            if any(x in o.get_path() for x in unWantedFolders):
                continue
            #logging.debug("file found: >" + str(o.get_path()))
            self.scan_file(application, o)               
            self.nbSrcFileScanned += 1
        
        # Final reporting in ApplicationPlugins.castlog
        logging.info("STATISTICS for AIA expectation: Number of peoplesoft sources scanned : " + str(self.nbSrcFileScanned))
        logging.info("STATISTICS for AIA expectation: Number of objects in violation for SQL injection: " + str(self.nbObjectInViolationForSQLExec))
        logging.info("STATISTICS for AIA expectation: Number of objects in violation for XSS: " + str(self.nbObjectInViolationForXSS))
        logging.info("STATISTICS for AIA expectation: Number of objects in violation for Avoid File: " + str(self.nbObjectInViolationAvoidFile))
        logging.info("STATISTICS for AIA expectation: Number of objects in violation for AvoidOSCommand: " + str(self.nbObjectInViolationAvoidOSCommand))
        logging.info("STATISTICS for AIA expectation: Number of objects in violation for LogForging: " + str(self.nbObjectInViolationLogForging))
    
     
def getfilebyencode(path):
            try:
                result= open(path, 'r', encoding="utf8")
            except UnicodeDecodeError:
                result= open(path, 'r')
            return result
          
def checkskippattern(self,  line):
        result = False
        for spattern in self.skippattern:
            if line.find(str(spattern)) is not -1: 
                result= True
        return result  