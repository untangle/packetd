"""Tests geoip plugin"""
# pylint: disable=no-self-use
import subprocess
import unittest
import runtests.test_registry as test_registry
import runtests.remote_control as remote_control

class GeoipTests(unittest.TestCase):

    @staticmethod
    def module_name():
        """module_name unittest method"""
        return "geoip"

    def initial_setup(self):
        """initial_setup unittest method"""
        subprocess.call("nft flush table inet test 2>/dev/null || true", shell=True)
        subprocess.call("nft add table inet test", shell=True)
        subprocess.call('nft add chain inet test filter-rules "{ type filter hook forward priority 0 ; }"', shell=True)

    def setUp(self):
        print()

    def test_000_client_is_online(self):
        """test the client is online"""
        result = remote_control.is_online()
        assert result == 0

    def test_010_reject_us(self):
        """verify a reject rule works using server_country"""
        subprocess.call("nft flush chain inet test filter-rules", shell=True)
        result1 = remote_control.run_command("ping -W5 -c1 4.2.2.1")
        subprocess.call("nft add rule inet test filter-rules ip daddr 4.2.2.2 counter", shell=True)
        subprocess.call("nft add rule inet test filter-rules ip daddr 4.2.2.2 dict session ct id server_country long_string US counter", shell=True)
        subprocess.call("nft add rule inet test filter-rules dict session ct id server_country long_string US counter reject", shell=True)
        result2 = remote_control.run_command("ping -W5 -c1 4.2.2.2")
        # subprocess.call("nft flush chain inet test filter-rules", shell=True)
        assert result1 == 0
        assert result2 != 0

    def test_011_drop_us(self):
        """verify a drop rule works using server_country"""
        subprocess.call("nft flush chain inet test filter-rules", shell=True)
        result1 = remote_control.run_command("ping -W5 -c1 4.2.2.1")
        subprocess.call("nft add rule inet test filter-rules ip daddr 4.2.2.2 counter", shell=True)
        subprocess.call("nft add rule inet test filter-rules ip daddr 4.2.2.2 dict session ct id server_country long_string US counter", shell=True)
        subprocess.call("nft add rule inet test filter-rules dict session ct id server_country long_string US counter drop", shell=True)
        result2 = remote_control.run_command("ping -W1 -c1 4.2.2.2")
        # subprocess.call("nft flush chain inet test filter-rules", shell=True)
        assert result1 == 0
        assert result2 != 0

    def final_tear_down(self):
        """final_tear_down unittest method"""
        subprocess.call("nft flush chain inet test filter-rules", shell=True)

test_registry.register_module("geoip", GeoipTests)
