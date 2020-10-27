import cast_upgrade_1_6_5 # @UnusedImport
import unittest
from cast.application.test import run
from cast.application import create_postgres_engine



class Test(unittest.TestCase):
    def test1(self):
        
        #run(kb_name='idms_local', application_name='idms', engine=create_postgres_engine(port=2282))
        run(kb_name='psoft_local', application_name='psoftcwe', engine=create_postgres_engine(port=2282))
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()