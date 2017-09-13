import unittest
import cast.analysers.test

class Test(unittest.TestCase):
    def testRegisterPlugin(self):
        
        # instanciate a UA analyzer for 'PeopleSoft' language defined by <category name="PeopleSoft" rid="2">
        # see http://cast-projects.github.io/Extension-SDK/doc/code_reference.html?highlight=uatestanalysis#cast.analysers.test.UATestAnalysis
        analysis = cast.analysers.test.UATestAnalysis('PeopleSoft')
        
        #add_selection for folder under "tests" Eclipse folder, relative reference
        analysis.add_selection('test_cases')
        analysis.set_verbose()
        analysis.run()
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
