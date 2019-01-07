"""settings_tests tests the settings API"""
# pylint: disable=no-self-use
# pylint: disable=too-many-public-methods
# pylint: disable=protected-access
import subprocess
import unittest
import json
import sys
import runtests.test_registry as test_registry

def get_settings(attributes=None, seperator="/"):
    """Gets the current settings and returns the JSON Object or None if there is any error"""
    if attributes is None:
        result = subprocess.run('curl -m 5 -X GET -s -o - -H "Content-Type: application/json; charset=utf-8" "http://localhost/api/settings"', shell=True, stdout=subprocess.PIPE)
    else:
        subpath = seperator.join(map(str, attributes))
        result = subprocess.run('curl -m 5 -X GET -s -o - -H "Content-Type: application/json; charset=utf-8" "http://localhost/api/settings/%s"' % subpath, shell=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        return None
    else:
        return json.loads(result.stdout.decode('utf-8'))

def trim_settings(attributes, seperator="/"):
    """Trims the current settings"""
    if attributes is None:
        result = subprocess.run('curl -m 5 -X DELETE -s -o - -H "Content-Type: application/json; charset=utf-8" "http://localhost/api/settings"', shell=True, stdout=subprocess.PIPE)
    else:
        subpath = seperator.join(map(str, attributes))
        result = subprocess.run('curl -m 5 -X DELETE -s -o - -H "Content-Type: application/json; charset=utf-8" "http://localhost/api/settings/%s"' % subpath, shell=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        return None
    else:
        return json.loads(result.stdout.decode('utf-8'))

def set_settings(attributes, settings, seperator="/"):
    """Sets the current settings to the provided JSON object"""
    if attributes is None:
        result = subprocess.run('curl -m 5 -X POST -s -o - -H "Content-Type: application/json; charset=utf-8" -d \'%s\' "http://localhost/api/settings"' % json.dumps(settings), shell=True, stdout=subprocess.PIPE)
    else:
        subpath = seperator.join(map(str, attributes))
        result = subprocess.run('curl -m 5 -X POST -s -o - -H "Content-Type: application/json; charset=utf-8" -d \'%s\' "http://localhost/api/settings/%s"' % (json.dumps(settings), subpath), shell=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        return None
    else:
        return json.loads(result.stdout.decode('utf-8'))

class SettingsTests(unittest.TestCase):
    """SettingsTests tests the settings API"""

    initial_settings = None

    @staticmethod
    def module_name():
        """module_name unittest method"""
        return "settings"

    def initial_setup(self):
        """initial_setup unittest method"""
        self.initial_settings = get_settings()

    def setUp(self):
        print()

    def test_001_get_settings(self):
        """Get the settings"""
        settings = get_settings()
        assert settings != None

    def test_002_get_settings_subparts(self):
        """"Gets all the attributes of the root settings object individually and verifies them"""
        settings = get_settings()
        print(settings)
        for i in settings:
            attr = get_settings([i])
            assert attr == settings[i]
            if isinstance(attr, type({})):
                for j in attr:
                    attr2 = get_settings([i, j])
                    assert attr2 == attr[j]
        assert settings != None

    def test_003_get_settings_subpart_missing(self):
        """Get some non-existant settings and verify it produces an error"""
        result1 = get_settings(['fakepart1', 'fakepart2', 'fakepart3'])
        assert 'error' in result1

    def test_004_get_settings_array_index(self):
        """Get the subpath of an object including an array with an index"""
        result1 = set_settings(['fakearray1'], [0, 1, 2, 3, 4, 5, 6])
        result2 = get_settings(['fakearray1', 3])
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2 == 3

    def test_005_get_settings_missing(self):
        """Get a missing setting and makes sure an error is returned"""
        fname = sys._getframe().f_code.co_name
        result1 = get_settings([1, 2, fname, 3])
        assert 'error' in result1
        assert 'missing' in result1.get('error')

    def test_010_set_settings_string(self):
        """Set the fakepart1 attribute of the root settings object to a string"""
        fname = sys._getframe().f_code.co_name
        result1 = set_settings(['fakepart1'], fname)
        result2 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1') == fname

    def test_011_set_settings_int(self):
        """Set the fakepart1 attribute of the root settings object to a int"""
        result1 = set_settings(['fakepart1'], 123)
        result2 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1') == 123

    def test_012_set_settings_float(self):
        """Set the fakepart1 attribute of the root settings object to a int"""
        result1 = set_settings(['fakepart1'], 123.123)
        result2 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1') == 123.123

    def test_013_set_settings_null(self):
        """Set the fakepart1 attribute of the root settings object to a int"""
        result1 = set_settings(['fakepart1'], None)
        result2 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert 'fakepart1' in result2
        assert result2.get('fakepart1') is None

    def test_014_set_settings_array(self):
        """Set the fakepart1 attribute of the root settings object to an array"""
        result1 = set_settings(['fakepart1'], [1, "abc"])
        result2 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1') == [1, "abc"]

    def test_015_set_settings_doubleslash(self):
        """Set the fakepart1//fakepart2//fakepart3 attribute of the root settings object"""
        fname = sys._getframe().f_code.co_name
        result1 = set_settings(['fakepart1', 'fakepart2', 'fakepart3'], fname, seperator="//")
        result2 = get_settings(seperator="//")
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1').get('fakepart2').get('fakepart3') == fname

    def test_016_set_settings_2layer(self):
        """Set the fakepart1 attribute of the root settings object to a JSON object"""
        fname = sys._getframe().f_code.co_name
        result1 = set_settings(['fakepart1'], {'fakepart2':fname})
        result2 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1').get('fakepart2') == fname

    def test_017_set_settings_3layer(self):
        """Set the fakepart1 attribute of the root settings object to a multi-layer JSON object"""
        fname = sys._getframe().f_code.co_name
        result1 = set_settings(['fakepart1'], {'fakepart2':{'fakepart3':fname}})
        result2 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1').get('fakepart2').get('fakepart3') == fname

    def test_018_set_settings_subpart_deeper(self):
        """Set the fakepart1/fakepart2 attribute of the root settings object to a JSON object"""
        fname = sys._getframe().f_code.co_name
        result1 = set_settings(['fakepart1', 'fakepart2'], {'fakepart3':fname})
        result2 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1').get('fakepart2').get('fakepart3') == fname

    def test_019_set_settings_array_index(self):
        """Set the fakepart1 attribute of the root settings object to an array"""
        result1 = set_settings(['fakearray1'], [0, 1, 2, 3, 4, 5, 6])
        result2 = get_settings(['fakearray1'])
        result3 = set_settings(['fakearray1', 2], "foo")
        result4 = get_settings(['fakearray1'])
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2 == [0, 1, 2, 3, 4, 5, 6]
        assert result3 != None
        assert result3.get('result') == 'OK'
        assert result4 != None
        assert result4 == [0, 1, "foo", 3, 4, 5, 6]

    def test_030_trim_settings(self):
        """Set the fakepart1/fakepart2 attribute of the root settings object and then trim it"""
        fname = sys._getframe().f_code.co_name
        result1 = set_settings(['fakepart1'], {'fakepart2':fname})
        result2 = get_settings()
        result3 = trim_settings(['fakepart1'])
        result4 = get_settings()
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1').get('fakepart2') == fname
        assert result3 != None
        assert result3.get('result') == 'OK'
        assert result4 != None
        assert result4.get('fakepart1') is None

    def test_031_trim_settings_nonexistant(self):
        """Trim a non-existant settings from the root settings object"""
        fname = sys._getframe().f_code.co_name
        result1 = trim_settings([fname])
        assert result1 != None
        assert result1.get('result') == 'OK'

    def test_032_trim_settings_nondict(self):
        """Trim a path that doesnt make sense"""
        fname = sys._getframe().f_code.co_name
        result1 = set_settings(['fakepart1', 'fakepart2'], fname, seperator="//")
        result2 = get_settings(seperator="//")
        result3 = trim_settings(['fakepart1', 'fakepart2', 'fakepart3'])
        assert result1 != None
        assert result1.get('result') == 'OK'
        assert result2 != None
        assert result2.get('fakepart1').get('fakepart2') == fname
        assert result3 != None
        assert result3.get('error') != None

    def final_tear_down(self):
        """final_tear_down unittest method"""
        set_settings(None, self.initial_settings)

test_registry.register_module("settings", SettingsTests)
