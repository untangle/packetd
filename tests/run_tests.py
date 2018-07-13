#!/usr/bin/python3 -u
import sys
import getopt
import signal
import os
import time
import traceback
import time
import datetime
sys.path.insert(0, './usr/lib/python%d.%d/' % sys.version_info[:2])

import unittest
import tests

orig_stdout = sys.stdout
orig_stderr = sys.stderr
exit_flag = False
interrupt_count = 0

class ArgumentParser(object):
    def __init__(self):
        self.client_ip = "192.0.2.2"
        self.host_username = None
        self.host_key_file = None
        self.verbosity = 2 # changed to default 2 because jcoffin
        self.logfile = '/tmp/unittest.log'
        self.fastfail = False
        self.repeat = False
        self.repeat_count = None
        self.external_intf_id = 1
        self.internal_intf_id = 2
        self.suites_to_run = ['all']
        self.suites_to_exclude = []
        self.tests_to_run = ['all']
        self.tests_to_exclude = []
        self.quick_tests_only = False

    def set_client_ip( self, arg ):
        self.client_ip = arg

    def set_username( self, arg ):
        self.username = arg

    def set_keyfile( self, arg ):
        self.password = arg

    def set_logfile( self, arg ):
        self.logfile = arg

    def set_fastfail( self, arg ):
        self.fastfail = True

    def set_repeat( self, arg ):
        self.repeat = True

    def set_repeat_count( self, arg ):
        self.repeat = True
        self.repeat_count = int(arg)

    def set_suites_to_run( self, arg ):
        self.suites_to_run = arg.split(",")

    def set_suites_to_exclude( self, arg ):
        self.suites_to_exclude = arg.split(",")

    def set_tests_to_run( self, arg ):
        self.tests_to_run = arg.split(",")

    def set_tests_to_exclude( self, arg ):
        self.tests_to_exclude = arg.split(",")

    def increase_verbosity( self, arg ):
        self.verbosity += 1

    def set_external_intf_id( self, arg ):
        self.external_intf_id = arg

    def set_internal_intf_id( self, arg ):
        self.internal_intf_id = arg

    def set_quick_tests_only( self, arg ):
        self.quick_tests_only = True

    def parse_args( self ):
        handlers = {
            '-h' : self.set_client_ip,
            '-u' : self.set_username,
            '-i' : self.set_keyfile,
            '-l' : self.set_logfile,
            '-v' : self.increase_verbosity,
            '-q' : self.set_fastfail,
            '-r' : self.set_repeat,
            '-c' : self.set_repeat_count,
            '-t' : self.set_suites_to_run,
            '-T' : self.set_tests_to_run,
            '-e' : self.set_suites_to_exclude,
            '-E' : self.set_tests_to_exclude,
            '-d' : self.set_external_intf_id,
            '-s' : self.set_internal_intf_id,
            '-z' : self.set_quick_tests_only,
        }

        try:
            (optlist, args) = getopt.getopt(sys.argv[1:], 'h:u:i:l:d:s:t:T:e:E:vqrc:xz')
            for opt in optlist:
                handlers[opt[0]](opt[1])
            return args
        except getopt.GetoptError as exc:
            print(exc)
            printUsage()
            exit(1)

def printUsage():
    sys.stderr.write( """\
%s Usage:
  optional args:
    -h <host>  : client host IP (behind Untangle)
    -u <user>  : client host SSH login
    -i <file>  : client host SSH identity (key) file
    -l <file>  : log file
    -d <int>   : interface ID of the external interface (outside) default: 1
    -s <int>   : interface ID of the internal interface (client) default: 2
    -t <suite> : comma seperated list test suites to run (default: "all") (exm: "web-filter,ad-blocker")
    -T <test>  : comma seperated list tests within suites to run (default: "all") (exm: "test_010_clientOnline")
    -e <suite> : comma seperated list test suites to EXCLUDE (default: "all") (exm: "web-filter,ad-blocker")
    -E <test>  : comma seperated list tests within suites to EXCLUDE (default: "all") (exm: "test_010_clientOnline")
    -v         : verbose (can be specified more than one time)
    -q         : quit on first failure
    -r         : repeat test indefinitely or until repeat count if specified (or until failure if -q is specified)
    -c <count> : repeat test count
    -z         : skip lengthly test suites
""" % sys.argv[0] )

def signal_handler(signal, frame):
    global orig_stdout, exit_flag, interrupt_count
    interrupt_count = interrupt_count + 1
    orig_stdout.write("Interrupt...\n")
    orig_stdout.flush()
    if interrupt_count > 4:
        sys.exit(1)
    else:
        exit_flag = True;

def exit(code):
    global parser
    if (code != 0):
        print("")
        print("More details found in %s" % parser.logfile)
    sys.exit(code)

def run_test_suite(suite):
    global parser
    global logfile
    global exit_flag
    
    if exit_flag:
        return
    
    print("== testing %s ==" % suite.moduleName())
    tests_list = unittest.TestLoader().loadTestsFromTestCase(suite)
    failCount = 0
    skipCount = 0  # number of skipped tests.
    totalCount = 0
    timeString = ""
    suiteStartTime = time.time()

    sys.stdout = logfile
    sys.stderr = logfile
    if "initialSetUp" in dir(suite):
        try:
            suite.initialSetUp(suite)
        except Exception as e:
            print("initialSetUp exception: ")
            traceback.print_exc()
            unittest.skip("initialSetUp exception: ")(suite)
    sys.stdout = orig_stdout
    sys.stderr = orig_stderr

    for test in tests_list:
        test_name = test._testMethodName

        if not ( test_name in parser.tests_to_run or "all" in parser.tests_to_run ):
            continue
        if test_name in parser.tests_to_exclude:
            continue

        sys.stdout = logfile
        sys.stderr = logfile

        testStartTime = time.time()

        print("\n\n")
        print("="*70)
        print(test_name + " start [" + time.strftime("%Y-%m-%dT%H:%M:%S") + "]")
        tests.global_functions.set_test_start_time()
        results = unittest.TextTestRunner( stream=logfile, verbosity=parser.verbosity ).run(test)
        print(test_name + " end   [" + time.strftime("%Y-%m-%dT%H:%M:%S") + "]")
        print("="*70)
        sys.stdout.flush
        tests.global_functions.set_previous_test_name( test_name )
        
        testElapsedTime = time.time() - testStartTime
        timeString = "[%.1fs]" % testElapsedTime

        sys.stdout = orig_stdout
        sys.stderr = orig_stderr

        if exit_flag:
            break
        
        totalCount += 1
        if (len(results.failures) > 0 or len(results.errors) > 0):
            print("Test FAILED  : %s %s" % (test_name, timeString))
            failCount += 1
            if (parser.fastfail):
                exit_flag = True
                # we return here, don't break because we dont
                # want to run finalTearDown
                return failCount, skipCount, totalCount
        elif (len(results.skipped) > 0):
            print("Test skipped : %s %s" % (test_name, timeString))
            skipCount += 1
        else:
            print("Test success : %s %s " % (test_name, timeString))

    if "finalTearDown" in dir(suite):
        try:
            suite.finalTearDown(suite)
        except Exception as e:
            print("finalTearDown exception: ")
            traceback.print_exc( e )

    suiteElapsedTime = time.time() - suiteStartTime
    print("== testing %s [%.1fs] ==" % (suite.moduleName(),suiteElapsedTime))
    return failCount, skipCount, totalCount

# Verify the test enviroment is setup correctly
def run_environment_tests():
    global parser
    global logfile
    suite = unittest.TestLoader().loadTestsFromTestCase(tests.TestEnvironmentTests)
    # results = unittest.TextTestRunner( stream=logfile, verbosity=parser.verbosity ).run( suite )
    print("== testing environment ==")
    for test in suite:
        results = unittest.TextTestRunner( stream=logfile, verbosity=parser.verbosity ).run( test )
        if exit_flag:
            break
        if (len(results.failures) > 0 or len(results.errors) > 0):
            print("Test FAILED  : %s " % test._testMethodName)
            print("The test enviroment is not configured correctly. Aborting...")
            exit(1) # always fast fail on basic test environment tests
        else:
            print("Test success : %s " % test._testMethodName)
    print("== testing environment ==")

signal.signal(signal.SIGINT, signal_handler)

parser = ArgumentParser()
script_args = parser.parse_args()
logfile = open(parser.logfile, 'w')

if (parser.client_ip != None):
    tests.remote_control.client_ip    = parser.client_ip
if (parser.host_username != None):
    tests.remote_control.host_username = parser.host_username
if (parser.host_key_file != None):
    tests.remote_control.host_key_file  = parser.host_key_file
tests.remote_control.verbosity   = parser.verbosity
tests.remote_control.logfile = logfile
tests.remote_control.interface = int(parser.internal_intf_id)
tests.remote_control.interface_external = int(parser.external_intf_id)
tests.remote_control.quick_tests_only = parser.quick_tests_only

if ("environment" in parser.suites_to_run or "all" in parser.suites_to_run) and "environment" not in parser.suites_to_exclude:
    run_environment_tests()

if exit_flag:
    sys.exit(0)

if "all" in parser.suites_to_run:
    parser.suites_to_run = tests.test_registry.all_modules()

# remove excluded tests
for test_name in parser.suites_to_exclude:
    if test_name in parser.suites_to_run:
        parser.suites_to_run.remove(test_name)

start_time = time.time()
total_count = 0
fail_count = 0
skip_count = 0

while True:
    for module in parser.suites_to_run:
        if exit_flag == True:
            break
        if module == "environment":
            continue
        test_clz = tests.test_registry.get_test(module)
        if test_clz == None:
           print("Unable to find tests for \"%s\"" % module)
           exit(1)
        sub_fail_count, sub_skip_count, sub_total_count = run_test_suite(test_clz)
        fail_count  += sub_fail_count
        total_count += sub_total_count
        skip_count  += sub_skip_count

    if exit_flag == True:
        break
    if not parser.repeat:
        break
    if parser.repeat_count != None:
        parser.repeat_count = parser.repeat_count-1
        if parser.repeat_count < 1:
            break

elapsedTime = time.time() - start_time
    
print("")
print("Tests complete. [%.1f seconds]" % elapsedTime)
print("%s passed, %s skipped, %s failed" % (total_count-fail_count-skip_count, skip_count, fail_count))
print("")
if total_count > 0:
    print("Total          : %4i" % total_count)
    print("Passed         : %4i" % (total_count-fail_count-skip_count))
    print("Skipped        : %4i" % (skip_count))
    print("Passed/Skipped : %4i [%6.2f%%]" % (total_count-fail_count, (100*(total_count-fail_count)/total_count)))
    print("Failed         : %4i [%6.2f%%]" % (fail_count, 100*fail_count/total_count))
    print("")
print("More details found in %s" % parser.logfile)

exit(fail_count)
