"""Tests packetd playback functionality"""
# pylint: disable=no-self-use
import subprocess
import unittest
import time
import os
import tests.test_registry as test_registry

def packetd_traffic_bypass():
    """Tells packetd to bypass real traffic"""
    subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"TRUE\"}' 'http://localhost/api/control/traffic' >> /tmp/subproc.out", shell=True)

def packetd_traffic_resume():
    """Tells packetd to resume real traffic"""
    subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"bypass\":\"FALSE\"}' 'http://localhost/api/control/traffic' >> /tmp/subproc.", shell=True)

def download_playback_file(filename):
    """download the playback file"""
    subprocess.call("rm -f /tmp/" + filename, shell=True)
    subprocess.call("wget -q -P /tmp http://test.untangle.com/packetd/" + filename, shell=True)

def playback_start(filename, filehash, playspeed):
    """start the playback file"""
    fullpath = "/tmp/" + filename
    md5sum = get_file_md5(fullpath)
    print("CHECKING FILENAME:%s MD5:%s" % (fullpath,md5sum))
    if (md5sum != filehash):
        download_playback_file(filename)
        md5sum = get_file_md5(fullpath)
        print("DOWNLOAD FILENAME:%s MD5:%s" % (fullpath,md5sum))
    assert md5sum == filehash
    result = subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{\"filename\":\"%s\",\"speed\":\"%i\"}' 'http://localhost/api/warehouse/playback' >> /tmp/subproc.out" % (fullpath, playspeed), shell=True)
    return result

def playback_cleanup():
    """start the playback file"""
    result = subprocess.call("curl -X POST -s -o - -H 'Content-Type: application/json; charset=utf-8' -d '{}' 'http://localhost/api/warehouse/cleanup' >> /tmp/subproc.out", shell=True)
    return result

def playback_wait():
    """wait on a playback to finish, returns 0 on success, 1 if timeout before 30 seconds"""
    counter = 0
    busy = 1
    end_time = time.time()+30
    while busy != 0 and time.time() < end_time:
        counter += 1
        time.sleep(.05)
        check = subprocess.Popen(["curl", "http://localhost/api/warehouse/status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = str(check.communicate()[0])
        if "IDLE" in result:
            return 0
    return 1

def read_dict():
    """return the whole dict as a string"""
    dictfile = open("/proc/net/dict/all", "r")
    rawdata = dictfile.read()
    dictfile.close()
    return rawdata

def read_dict_session(ctid):
    """return the dict for a specific session"""
    dictfile = open("/proc/net/dict/read", "r+")
    dictfile.write("table=session,key_int=" + ctid + ",")
    rawdata = dictfile.read()
    dictfile.close()
    return rawdata

def get_file_md5(filename):
    """return the md5sum for the specified file"""
    if os.path.isfile(filename):
        check = subprocess.Popen(["md5sum", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = check.communicate()[0]
        return output.split()[0]
    else:
        return "0"

def clear_dict():
    """Clears the dictionary of the fack session IDs in the playbacks"""
    dictfile = open("/proc/net/dict/delete", "r+")
    dictfile.write("table=session,key_int=" + PlaybackTests.http_ctid + ",")
    dictfile.close()

    dictfile = open("/proc/net/dict/delete", "r+")
    dictfile.write("table=session,key_int=" + PlaybackTests.https_ctid + ",")
    dictfile.close()

    dictfile = open("/proc/net/dict/delete", "r+")
    dictfile.write("table=session,key_int=" + PlaybackTests.hint_ctid + ",")
    dictfile.close()

class PlaybackTests(unittest.TestCase):
    "Tests the playback functionality"

    play_file_name = "playtest.cap"
    play_file_hash = "f8388c823679da7db0a4cb7856bf717c".encode('UTF-8')

    hint_file_name = "dnshint.cap"
    hint_file_hash = "33e7c4182a233ad689811467a4d92608".encode('UTF-8')

    revd_file_name = "dnsreverse.cap"
    revd_file_hash = "be323000b89a2b6c29591832c895c850".encode('UTF-8')

    https_ctid = "4073347072"
    http_ctid = "4073346816"
    hint_ctid = "4107412992"
    revd_ctid = "4107413760"
    normtime = 0.0

    @staticmethod
    def module_name():
        """module_name unittest method"""
        return "playback"

    def initial_setup(self):
        """initial_setup unittest method"""
        packetd_traffic_bypass()

    def setUp(self):
        """setUp unittest method"""
        print()
        clear_dict()

    def test_010_check_empty_table(self):
        """verify the ctids aren't in the dictionary"""
        rawdata = read_dict()
        assert "table: session key_int: " + PlaybackTests.http_ctid not in rawdata
        assert "table: session key_int: " + PlaybackTests.https_ctid not in rawdata
        assert "table: session key_int: " + PlaybackTests.hint_ctid not in rawdata

    def test_020_playback_capture_file_normal(self):
        """playback the capture file and wait for it to finish"""
        assert playback_start(PlaybackTests.play_file_name, PlaybackTests.play_file_hash, 100) == 0
        begtime = time.time()
        assert playback_wait() == 0
        endtime = time.time()
        PlaybackTests.normtime = (endtime - begtime)
        print("NORMTIME: " + str(PlaybackTests.normtime))
        rawdata = read_dict_session(PlaybackTests.http_ctid)
        playback_cleanup()
        assert rawdata != ""

    def test_021_playback_capture_file_speedup(self):
        """playback the capture file and wait for it to finish"""
        assert playback_start(PlaybackTests.play_file_name, PlaybackTests.play_file_hash, 200) == 0
        begtime = time.time()
        assert playback_wait() == 0
        endtime = time.time()
        fasttime = (endtime - begtime)
        calctime = (PlaybackTests.normtime / 2)
        print("FASTTIME:" + str(fasttime) + "  TARGET:" + str(calctime))
        assert fasttime < calctime + 4
        assert fasttime > calctime - 4
        rawdata = read_dict_session(PlaybackTests.http_ctid)
        playback_cleanup()
        assert rawdata != ""

    def test_022_playback_capture_file_slowdown(self):
        """playback the capture file and wait for it to finish"""
        assert playback_start(PlaybackTests.play_file_name, PlaybackTests.play_file_hash, 50) == 0
        begtime = time.time()
        assert playback_wait() == 0
        endtime = time.time()
        slowtime = (endtime - begtime)
        calctime = (PlaybackTests.normtime * 2)
        print("SLOWTIME:" + str(slowtime) + "  TARGET:" + str(calctime))
        assert slowtime < calctime + 4
        assert slowtime > calctime - 4
        rawdata = read_dict_session(PlaybackTests.http_ctid)
        playback_cleanup()
        assert rawdata != ""

    def test_030_check_http_classify(self):
        """check classify HTTP session details in the dictionary"""
        assert playback_start(PlaybackTests.play_file_name, PlaybackTests.play_file_hash, 0) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.http_ctid)
        playback_cleanup()
        print(rawdata)
        assert "field: application_name string: HTTP" in rawdata
        assert "field: application_protochain string: /IP/TCP/HTTP" in rawdata

    def test_031_check_https_geoip(self):
        """check HTTPS session geoip details in the dictionary"""
        assert playback_start(PlaybackTests.play_file_name, PlaybackTests.play_file_hash, 0) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.https_ctid)
        playback_cleanup()
        assert "field: server_country string: JP" in rawdata

    def test_032_check_https_sni(self):
        """check HTTPS session sni details in the dictionary"""
        assert playback_start(PlaybackTests.play_file_name, PlaybackTests.play_file_hash, 0) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.https_ctid)
        playback_cleanup()
        assert "field: ssl_sni string: www.japan.go.jp" in rawdata

    def test_033_check_https_cert(self):
        """check HTTPS session cert details in the dictionary"""
        assert playback_start(PlaybackTests.play_file_name, PlaybackTests.play_file_hash, 0) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.https_ctid)
        playback_cleanup()
        assert "field: certificate_subject_cn string: www.japan.go.jp" in rawdata

    def test_040_check_dns_hint(self):
        """check for DNS hint in the dictionary"""
        assert playback_start(PlaybackTests.hint_file_name, PlaybackTests.hint_file_hash, 0) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.hint_ctid)
        playback_cleanup()
        assert "field: server_dns_hint string: www.yahoo.com" in rawdata

    def test_050_check_dns_reverse(self):
        """check for reverse DNS in the dictionary"""
        assert playback_start(PlaybackTests.revd_file_name, PlaybackTests.revd_file_hash, 0) == 0
        assert playback_wait() == 0
        rawdata = read_dict_session(PlaybackTests.revd_ctid)
        playback_cleanup()
        assert "field: server_reverse_dns string: google-public-dns-a.google.com" in rawdata

    def final_tear_down(self):
        """final_tear_down"""
        playback_cleanup()
        packetd_traffic_resume()

test_registry.register_module("playback", PlaybackTests)
