import cast_upgrade_1_5_6 # @UnusedImport
from cast.application import ApplicationLevelExtension, ReferenceFinder
import logging

class PsftSecuExtension(ApplicationLevelExtension):

    #initialization of variables
    nbSrcFileScanned = 0
    nbObjectInViolationForSQLExec = 0
    
    def scan_file(self, application, _file):
        #logging.debug("INIT scan_file : file > " +str(_file))
        #initialization
        isInViolationForSQL = False
        isInViolationForXSS = False
        
        # one RF for multiples patterns # TODO abandoned for performance reasons
        rfCall = ReferenceFinder()
        #rfCall.add_pattern('COMMENTEDline', before='', element = "\n......\*", after='')
        rfCall.add_pattern('SQLExecStatement', before='', element = "[sS][qQ][lL][eE][xX][eE][cC][ \(\r\n\t]+.*", after='')
               
        # search all patterns in current program
        try:
            references = [reference for reference in rfCall.find_references_in_file(_file)]
        except FileNotFoundError:
            logging.warning("Wrong file or file path, from Vn-1 or previous " + str(_file))
        else:
            # for debugging and traversing the results
            for reference in references:
                logging.debug("DONE: reference found: >" +str(reference))
                if  reference.pattern_name=='SQLExecStatement':
                    logging.debug("GOTCHA1 ! Found SQLExec statement :" + str(reference.value)) 
                    # this is a violation - put the object in violation
                    isInViolationForSQL = True
                    # find the object behind this line of code... see MRO email 'functions' on ven. 12/05/2017 17:00 ...
                    _line_number = reference.bookmark.begin_line
                    specific_object = _file.find_most_specific_object(_line_number, 1)  # internal API used under the hood by ReferenceFinder API.
                    # TODO : do I need to check if same object will have multiple violations ?
                    # answer : no, the property is declared as sum, so it should work fine.
                    specific_object.save_violation('Psft_Security_CustomMetrics.Pcode_SQL_Injection', reference.bookmark)
        
            # reporting the violations for statistics / logging purpose - outside of the reference loop
            if isInViolationForSQL == True:
                self.nbObjectInViolationForSQLExec += 1
             
    def end_application(self, application):
         
        logging.debug("running code at the end of an application")
        #print("PRINT Running code at the end of an application")
        
        #declare ownership for all diags (this call also performs the required init cleaning)
        application.declare_property_ownership('Psft_Security_CustomMetrics.Pcode_SQL_Injection',['PSoft_Object'])
        application.declare_property_ownership('Psft_Security_CustomMetrics.Pcode_XSS_Injection',['PSoft_Object'])
        
        # list all files saved by PeopleSoft Analyzer
        #files = application.get_files(['PSoft_Object'])
        files = application.get_files()
         
        #looping through Psft objects
        for o in files:
            # check if file is analyzed source code, or if it generated (Unknown)
            if not o.get_path():
                continue
            # check if file is a program , skip the copybooks (for the moment at least)
            if not o.get_path().endswith('.src'):
                continue
            #cast.analysers.log.debug("file found: >" + str(o.get_path()))
            logging.debug("file found: >" + str(o.get_path()))
            self.scan_file(application, o)               
            self.nbSrcFileScanned += 1
        
        # Final reporting in ApplicationPlugins.castlog
        logging.info("STATISTICS for AIA expectation: Number of .cob sources scanned : " + str(self.nbSrcFileScanned))
        logging.info("STATISTICS for AIA expectation: Number of objects for SQL statement: " + str(self.nbObjectInViolationForSQLExec))