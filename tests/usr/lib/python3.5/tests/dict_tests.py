"""nf_dict tests"""
# pylint: disable=no-self-use
# pylint: disable=too-many-arguments
# pylint: disable=protected-access
import unittest
import sys
import threading
import tests.test_registry as test_registry

def add_entry(table, key, field, value, key_type="string", value_type="string"):
    """Add an entry to the dict"""
    if value_type == "string":
        value_type = "value"
    addstr = "table=%s,key_%s=%s,field=%s,%s=%s" % (table, key_type, key, field, value_type, value)
    print("Setting Value: " + addstr)
    f = open('/proc/net/dict/write', 'w')
    f.write(addstr)
    f.close()

def get_dict(table, key, key_type="string"):
    """Get a dict"""
    getstr = "table=%s,key_%s=%s" % (table, key_type, key)
    print("Setting Dict: " + getstr)
    f = open('/proc/net/dict/read', 'w+')
    f.write(getstr)
    result = f.read()
    print("Result: " + result)
    f.close()
    return result

def delete_dict(table, key, key_type="string"):
    """Get a dict"""
    getstr = "table=%s,key_%s=%s" % (table, key_type, key)
    print("Deleting Dict: " + getstr)
    f = open('/proc/net/dict/delete', 'w+')
    f.write(getstr)
    f.close()

class DictTests(unittest.TestCase):
    """DictTests"""

    @staticmethod
    def module_name():
        """module_name unittest method"""
        return "dict"

    def initial_setup(self):
        """initial_setup unittest method"""
        pass

    def setUp(self):
        """setUp unittest method"""
        print()

    def test_000_basic_test(self):
        """Basic test"""
        assert True

    def test_100_add_entry_string(self):
        """Tests saving a string type value"""
        fname = sys._getframe().f_code.co_name
        add_entry("test_session", "1234", "field", fname, "string", "string")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert fname in result

    def test_101_add_entry_int(self):
        """Tests saving a int type value"""
        add_entry("test_session", "1234", "field", 9999, "string", "int")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "9999" in result

    def test_102_add_entry_int64(self):
        """Tests saving a int64 type value"""
        add_entry("test_session", "1234", "field", 123456789123456789, "string", "int64")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "123456789123456789" in result

    def test_103_add_entry_bool(self):
        """Tests saving a bool type value"""
        add_entry("test_session", "1234", "field", "true", "string", "bool")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "true" in result

    def test_104_add_entry_ip(self):
        """Tests saving a ip type value"""
        add_entry("test_session", "1234", "field", "1.2.3.4", "string", "ip")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "1.2.3.4" in result

    def test_105_add_entry_ip6(self):
        """Tests saving a ip6 type value"""
        add_entry("test_session", "1234", "field", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "string", "ip6")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in result

    def test_106_add_entry_mac(self):
        """Tests saving a mac type value"""
        add_entry("test_session", "1234", "field", "11:22:33:44:55:66", "string", "mac")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "11:22:33:44:55:66" in result

    def test_200_add_entry_really_long_string(self):
        """Tests saving a string type value that is too long"""
        fname = sys._getframe().f_code.co_name
        fname = fname + "123457890"*2000
        fname = fname + "end_marker"
        add_entry("test_session", "1234", "field", fname, "string", "string")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        # FIXME - what is the anticipated result of doing such a thing? a truncated string?
        assert fname in result
        assert "end_market" not in result

    def test_201_add_entry_really_big_int(self):
        """Tests saving a int type value that is too big"""
        add_entry("test_session", "1234", "field", 123456789123456789123456789, "string", "int")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "123456789123456789123456789" not in result

    def test_202_add_entry_invalid_bool(self):
        """Tests saving a bool type value that makes no sense"""
        add_entry("test_session", "1234", "field", "foobar", "string", "bool")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "foobar" not in result

    def test_203_add_entry_invalid_ip(self):
        """Tests saving a ip type value that makes no sense"""
        add_entry("test_session", "1234", "field", "foobar", "string", "ip")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "foobar" not in result

    def test_204_add_entry_invalid_ip6(self):
        """Tests saving a ip type value that makes no sense"""
        add_entry("test_session", "1234", "field", "foobar", "string", "ip6")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "foobar" not in result

    def test_205_add_entry_invalid_mac(self):
        """Tests saving a ip type value that makes no sense"""
        add_entry("test_session", "1234", "field", "foobar", "string", "mac")
        result = get_dict("test_session", "1234", "string")
        delete_dict("test_session", "1234", "string")
        assert "foobar" not in result

    def test_900_load_test_string(self):
        """Tests saving a mac type value"""
        fname = sys._getframe().f_code.co_name
        for i in range(1000):
            itrstr = fname + str(i)
            add_entry("test_session", "1234", "field", itrstr, "string", "string")
            result = get_dict("test_session", "1234", "string")
            assert itrstr in result

    def load_test(self):
        """Tests saving a mac type value"""
        fname = sys._getframe().f_code.co_name
        for i in range(1000):
            itrstr = fname + str(i)
            add_entry("test_session", "1234", "field", itrstr, "string", "string")

    def test_901_load_test_string_threaded(self):
        """Tests saving a mac type value"""
        threads = []
        for _ in range(10):
            t = threading.Thread(target=self.load_test)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        result = get_dict("test_session", "1234", "string")
        assert "load_test999" in result

    def final_tear_down(self):
        """final_tear_down unittest method"""
        pass

test_registry.register_module("dict", DictTests)
