import subprocess
import unittest
import json
import time
import sys
import tests.test_registry as test_registry
import tests.remote_control as remote_control

class PlaybackTests(unittest.TestCase):

    @staticmethod
    def moduleName():
        return "playback"

    @staticmethod
    def initialSetUp(self):
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"TRUE\"}' 'http://localhost:8080/api/control/traffic' >> /tmp/subproc.out", shell=True)
        pass

    def setUp(self):
        print()

    def test_010_check_empty_table(self):
        '''make sure the ctid does not yet exist in the table'''
        dict = open("/proc/net/dict/read","r+")
        dict.write("table=session,key_int=4095221248")
        rawdata = dict.read()
        dict.close
        assert "table: session key_int: 4095221248" not in rawdata

    def test_020_playback_capture_file(self):
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"filename\":\"/temp/japan.cap\",\"speed\":\"2\"}' 'http://localhost:8080/api/warehouse/playback' >> /tmp/subproc.out", shell=True)
        counter = 0
        busy = 1
        while busy != 0 and counter < 30:
            counter += 1
            time.sleep(1)
            check = subprocess.Popen(["curl","http://localhost:8080/api/warehouse/status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = str(check.communicate()[0])
            print(result)
            if "IDLE" in result:
                busy = 0
        pass

    def test_030_check_country_code(self):
        dict = open("/proc/net/dict/read","r+")
        dict.write("table=session,key_int=4095221248")
        rawdata = dict.read()
        dict.close
        assert "field: server_country string: JP" in rawdata
        assert "table: session key_int: 4095221248" in rawdata

    @staticmethod
    def finalTearDown(self):
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"FALSE\"}' 'http://localhost:8080/api/control/traffic' >> /tmp/subproc.out", shell=True)
        pass

test_registry.register_module("playback", PlaybackTests)
