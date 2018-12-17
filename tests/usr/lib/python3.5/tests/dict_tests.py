"""nf_dict tests"""
# pylint: disable=no-self-use
import unittest
import tests.test_registry as test_registry

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

    def final_tear_down(self):
        """final_tear_down unittest method"""
        pass

test_registry.register_module("dict", DictTests)
