'''
@author: AGR
'''
import unittest
from cast.application.test import run

class Test(unittest.TestCase):


    def testName(self):
        run(kb_name='peoplesoft_local', application_name='eForce')

if __name__ == "__main__":
    unittest.main()
