"""status_tests tests the status API"""
# pylint: disable=no-self-use
# pylint: disable=too-many-public-methods
# pylint: disable=protected-access
import subprocess
import unittest
import json
import sys
import runtests.test_registry as test_registry

def get_status(str, seperator="/"):
    """Gets the specified status and returns the JSON Object or None if there is any error"""
    result = subprocess.run('curl -m 5 -X GET -s -o - -H "Content-Type: application/json; charset=utf-8" "http://localhost/api/status/%s"' % str, shell=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        return None
    else:
        return json.loads(result.stdout.decode('utf-8'))

class StatusTests(unittest.TestCase):
    """StatusTests tests the status API"""

    @staticmethod
    def module_name():
        """module_name unittest method"""
        return "status"

    def initial_setup(self):
        """initial_setup unittest method"""
        pass
        
    def setUp(self):
        print()

    def test_001_get_status_system(self):
        """Get the system status"""
        system_status = get_status("system")
        assert system_status != None
        assert system_status.get('loadavg') != None
        assert system_status.get('loadavg').get('last1min') != None
        assert system_status.get('meminfo') != None
        assert system_status.get('meminfo').get('mem_total') != None
        assert system_status.get('meminfo').get('mem_available') != None
        assert system_status.get('uptime') != None
        assert system_status.get('diskstats') != None
        assert system_status.get('rootfs') != None
        assert system_status.get('tmpfs') != None

    def test_002_get_status_sessions(self):
        """Get the sessions"""
        sessions = get_status("sessions")
        assert isinstance(sessions, list)
        if len(sessions) > 0:
            assert sessions[0].get("client_address") != None
            assert sessions[0].get("server_address") != None
            assert sessions[0].get("protocol") != None
            assert sessions[0].get("ip_protocol") != None

    def test_003_get_status_hardware(self):
        """Get the hardware status"""
        hardware_status = get_status("hardware")
        assert hardware_status.get("cpuinfo") != None
        assert hardware_status.get("cpuinfo").get("processors") != None
        assert len(hardware_status.get("cpuinfo").get("processors")) > 0
            
    def final_tear_down(self):
        """final_tear_down unittest method"""
        pass
        
test_registry.register_module("status", StatusTests)
