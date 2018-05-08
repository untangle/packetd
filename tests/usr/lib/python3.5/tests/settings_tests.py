import subprocess
import unittest
import tests.test_registry
import json

initial_settings = None

def get_settings(attributes=None):
    """Gets the current settings and returns the JSON Object or None if there is any error"""
    if attributes == None:
        result = subprocess.run('curl -X GET -s -o - -H "Content-Type: application/json; charset=utf-8" "http://localhost:8080/settings/get_settings"', shell=True, stdout=subprocess.PIPE)
    else:
        subpath = "/" + "/".join(map(str, attributes))
        result = subprocess.run('curl -X GET -s -o - -H "Content-Type: application/json; charset=utf-8" "http://localhost:8080/settings/get_settings/%s"' % subpath, shell=True, stdout=subprocess.PIPE)
        
    if result.returncode != 0:
        return None
    else:
        return json.loads(result.stdout.decode('utf-8'))

def set_settings(settings, attributes=None):
    """Sets the current settings to the provided JSON object"""
    if attributes == None:
        result = subprocess.run('curl -X POST -s -o - -H "Content-Type: application/json; charset=utf-8" -d \'%s\' "http://localhost:8080/settings/set_settings"' % json.dumps(settings), shell=True, stdout=subprocess.PIPE)
    else:
        subpath = "/" + "/".join(map(str, attributes))
        result = subprocess.run('curl -X POST -s -o - -H "Content-Type: application/json; charset=utf-8" -d \'%s\' "http://localhost:8080/settings/set_settings/%s"' % (json.dumps(settings),subpath), shell=True, stdout=subprocess.PIPE)
    return result.returncode

class SettingsTests(unittest.TestCase):

    @staticmethod
    def moduleName():
        return "settings"

    @staticmethod
    def initialSetUp(self):
        global initial_settings
        initial_settings = get_settings()
        pass

    def setUp(self):
        pass

    def test_00_basic_test(self):
        assert(True)

    def test_01_get_settings(self):
        settings = get_settings()
        assert(settings != None)

    def test_02_get_settings_subpart(self):
        settings = get_settings()
        for i in settings:
            attr = get_settings([i])
            assert(attr == settings[i])
            if type(attr) == type({}):
                for j in attr:
                    attr2 = get_settings([i,j])
                    assert(attr2 == attr[j])
        assert(settings != None)

    def test_03_get_settings_subpart_missing(self):
        settings = get_settings(['1','2','3'])
        assert('error' in settings)
        
    def test_10_set_settings_small(self):
        result1 = set_settings({'abcdef':'xyz123'},['fakeattribute'])
        result2 = get_settings()
        assert(result1 == 0)
        assert('fakeattribute' in result2)
        assert('abcdef' in result2['fakeattribute'])
        assert(result2['fakeattribute']['abcdef'] == 'xyz123')

    def test_11_set_settings_larger(self):
        result1 = set_settings({'abcdef':{'xyz':'123'}},['fakeattribute'])
        result2 = get_settings()
        assert(result1 == 0)
        assert('fakeattribute' in result2)
        assert('abcdef' in result2['fakeattribute'])
        assert('xyz' in result2['fakeattribute']['abcdef'])

    def test_13_set_settings_subpart_deeper(self):
        result1 = set_settings({'abcdef':'xyz123'},['fakeattribute','789'])
        result2 = get_settings()
        assert(result1 == 0)
        assert('fakeattribute' in result2)
        assert('789' in result2['fakeattribute'])
        assert('abcdef' in result2['fakeattribute']['789'])
        
    @staticmethod
    def finalTearDown(self):
        global initial_settings
        set_settings(initial_settings)
        pass
    
tests.test_registry.registerModule("settings", SettingsTests)
