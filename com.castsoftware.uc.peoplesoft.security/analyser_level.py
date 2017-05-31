import cast.analysers.ua
from cast.analysers import log, Bookmark
import os

class PeopleCodeSrcFile(cast.analysers.ua.Extension):

    def __init__(self):
        self.current_file_objects = []
    
    def start_file(self, _file):
        self.current_file_objects = []
        # do nothing
        log.info("start_file called with file = " + str(_file))
            
    def start_object(self, _object):
        # do nothing
        log.info("start_object called with object = " + str(_object))
            
    def end_object(self, _object):
        log.info("end_object called with object = " + str(_object))
        #print("end_object called with object = " + str(_object))
        self.current_file_objects.append(_object)
        
    def end_file(self, _file):
        # do the parsing here
        log.info("end_file called with file = " + str(_file))
        
        # performance need parsing line by line
        lineNb = 0
        nbSQLviolation = 0
        with open(_file.get_path(), 'r') as f:
            for line in f:
                lineNb +=1
                if "SqlExec" in line:
                    sqlExecBook = Bookmark(_file,lineNb,1,lineNb,-1)
                    log.info("About to create SQL injection violation at " + str(lineNb) + " for " + line)
                    #_object = 
                    #_object.save_violation('Psft_Security_CustomMetrics.Pcode_SQL_Injection', sqlExecBook)
                    nbSQLviolation += 1
                
        log.info("Beaucoup de violations" + str(nbSQLviolation))