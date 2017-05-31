'''
@author: AGR
'''
import unittest
from cast.application.test import run

class Test(unittest.TestCase):


    def testName(self):
        run(kb_name='psft_cwe2_local', application_name='Psft_CWE2_TC1')

if __name__ == "__main__":
    unittest.main()
