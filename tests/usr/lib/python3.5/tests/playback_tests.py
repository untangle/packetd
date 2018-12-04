import subprocess
import unittest
import json
import time
import os
import sys
import tests.test_registry as test_registry
import tests.remote_control as remote_control

class PlaybackTests(unittest.TestCase):

    file_hash = "fa0831b34e4e7fa5e6d56370dcd6d0be".encode('UTF-8')
    http_ctid = "4071800832"
    https_ctid = "4071803136"

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
        '''delete all our ctid's and verify they aren't in the dictionary'''
        dict = open("/proc/net/dict/delete","r+")
        dict.write("table=session,key_int=" + PlaybackTests.http_ctid + ",")
        dict.close()

        dict = open("/proc/net/dict/delete","r+")
        dict.write("table=session,key_int=" + PlaybackTests.https_ctid + ",")
        dict.close()

        dict = open("/proc/net/dict/all","r")
        rawdata = dict.read()
        dict.close()

        assert "table: session key_int: " + PlaybackTests.http_ctid not in rawdata
        assert "table: session key_int: " + PlaybackTests.https_ctid not in rawdata
    def test_020_download_capture_file(self):
        '''download the playback file needed for our tests'''
        if os.path.isfile("/tmp/playtest.cap"):
            check = subprocess.Popen(["md5sum","/tmp/playtest.cap"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = check.communicate()[0]
            hash = output.split()[0]
        else:
            hash = "missing"

        if hash != PlaybackTests.file_hash:
            result = subprocess.call("wget -q -P /tmp http://test.untangle.com/packetd/playtest.cap", shell=True)
        else:
            result = 0

        assert result == 0

    def test_030_playback_capture_file(self):
        '''playback the capture file and wait for it to finish'''
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"filename\":\"/tmp/playtest.cap\",\"speed\":\"1\"}' 'http://localhost:8080/api/warehouse/playback' >> /tmp/subproc.out", shell=True)
        counter = 0
        busy = 1
        while busy != 0 and counter < 10:
            counter += 1
            time.sleep(1)
            check = subprocess.Popen(["curl","http://localhost:8080/api/warehouse/status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = str(check.communicate()[0])
            if "IDLE" in result:
                busy = 0
        assert busy == 0

    def test_040_check_http(self):
        '''check HTTP session details in the dictionary'''
        dict = open("/proc/net/dict/read","r+")
        dict.write("table=session,key_int=" + PlaybackTests.http_ctid + ",")
        rawdata = dict.read()
        dict.close()
        assert "field: server_country string: US" in rawdata
        assert "field: application_name string: HTTP" in rawdata
        assert "field: application_protochain string: /IP/TCP/HTTP" in rawdata

    def test_041_check_https(self):
        '''check HTTPS session details in the dictionary'''
        dict = open("/proc/net/dict/read","r+")
        dict.write("table=session,key_int=" + PlaybackTests.https_ctid + ",")
        rawdata = dict.read()
        dict.close()
        assert "field: server_country string: JP" in rawdata
        assert "field: application_name string: SSL" in rawdata
        assert "field: application_protochain string: /IP/TCP/SSL" in rawdata

    def test_050_playback_cleanup(self):
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{}' 'http://localhost:8080/api/warehouse/cleanup' >> /tmp/subproc.out", shell=True)
        pass

    @staticmethod
    def finalTearDown(self):
        subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"FALSE\"}' 'http://localhost:8080/api/control/traffic' >> /tmp/subproc.out", shell=True)
        pass

test_registry.register_module("playback", PlaybackTests)
