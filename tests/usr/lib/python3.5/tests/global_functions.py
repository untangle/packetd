import os
import datetime

test_start_time = None
previous_test_name = None

def get_test_start_time():
    global test_start_time
    return test_start_time

def set_test_start_time():
    global test_start_time
    test_start_time = datetime.datetime.now()

def set_previous_test_name( name ):
    global previous_test_name
    previous_test_name = name

def get_previous_test_name():
    global previous_test_name
    return previous_test_name
