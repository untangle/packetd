import subprocess
import unittest
import json
import sys
import tests.test_registry as test_registry
import tests.remote_control as remote_control

class GeoipTests(unittest.TestCase):

    @staticmethod
    def moduleName():
        return "geoip"

    @staticmethod
    def initialSetUp(self):
        subprocess.call("nft flush table inet test 2>/dev/null || true", shell=True)
        subprocess.call("nft add table inet test", shell=True)
        subprocess.call('nft add chain inet test filter-rules "{ type filter hook forward priority 0 ; }"', shell=True)
        pass

    def setUp(self):
        pass

    def test_000_client_is_online(self):
        result = remote_control.is_online()
        assert (result == 0)

    def test_010_block_us(self):
        """verify a block rule works using remote_control"""
        # this test URL should NOT be blocked
        result1 = remote_control.run_command("ping -W5 -c1 4.2.2.1")
        subprocess.call("nft add rule inet test filter-rules dict session ct id server_country long_string US reject", shell=True)
        result2 = remote_control.run_command("ping -W5 -c1 4.2.2.1")
        subprocess.call("nft flush chain inet test filter-rules", shell=True)
        assert (result1 == 0)
        assert (result2 != 0)
    
    @staticmethod
    def finalTearDown(self):
        subprocess.call("nft flush chain inet test filter-rules", shell=True)
        pass
    
test_registry.register_module("geoip", GeoipTests)
