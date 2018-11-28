import subprocess
import unittest
import json
import time
import sys
import os
import tests.test_registry as test_registry
import tests.remote_control as remote_control

class PlaybackTests(unittest.TestCase):

#    geoip_ctid = "4288283904"
    geoip_ctid = "4187620608"

    @staticmethod
    def moduleName():
        return "playback"

    @staticmethod
    def initialSetUp(self):
        # turn on the traffic bypass flag
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"TRUE\"}' 'http://localhost:8080/api/control/traffic' >> /tmp/subproc.out", shell=True)
        pass

    def setUp(self):
        print()

    def test_010_check_empty_table(self):
        '''make sure the ctid does not yet exist in the table'''
        dict = open("/proc/net/dict/delete","r+")
        dict.write("table=session,key_int=" + PlaybackTests.geoip_ctid + ",")
        dict.close
        dict = open("/proc/net/dict/read","r+")
        dict.write("table=session,key_int=" + PlaybackTests.geoip_ctid + ",")
        rawdata = dict.read()
        dict.close
        assert "table: session key_int: " + PlaybackTests.geoip_ctid not in rawdata

    def test_020_download_capture_file(self):
        '''download the playback file needed for our tests'''
        result = subprocess.call("wget -q -P /tmp http://test.untangle.com/packetd/japan.cap", shell=True)
        assert result == 0

    def test_030_playback_capture_file(self):
        '''playback the capture file and wait for it to finish'''
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"filename\":\"/tmp/japan.cap\",\"speed\":\"1\"}' 'http://localhost:8080/api/warehouse/playback' >> /tmp/subproc.out", shell=True)
        counter = 0
        busy = 1
        while busy != 0 and counter < 10:
            counter += 1
            time.sleep(1)
            check = subprocess.Popen(["curl","http://localhost:8080/api/warehouse/status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = str(check.communicate()[0])
            print(result)
            if "IDLE" in result:
                busy = 0
        assert busy == 0

    def test_031_check_country_code(self):
        '''check for the country code in the dictionary'''
        dict = open("/proc/net/dict/read","r+")
        dict.write("table=session,key_int=" + PlaybackTests.geoip_ctid + ",")
        rawdata = dict.read()
        dict.close
        assert "field: server_country string: JP" in rawdata
        assert "table: session key_int: " + PlaybackTests.geoip_ctid in rawdata

    def test_032_playback_cleanup(self):
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{}' 'http://localhost:8080/api/warehouse/cleanup' >> /tmp/subproc.out", shell=True)
        pass

    @staticmethod
    def finalTearDown(self):
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"FALSE\"}' 'http://localhost:8080/api/control/traffic' >> /tmp/subproc.out", shell=True)
        if os.path.exists("/tmp/japan.cap"):
            os.remove("/tmp/japan.cap")
        pass

test_registry.register_module("playback", PlaybackTests)
