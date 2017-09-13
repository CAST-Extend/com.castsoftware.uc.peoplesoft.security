<<<<<<< HEAD:tests/test_application_level.py
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
=======
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
>>>>>>> parent of 4a6588b... 1st functional Version:com.castsoftware.uc.peoplesoft.security/tests/test_application_level.py
