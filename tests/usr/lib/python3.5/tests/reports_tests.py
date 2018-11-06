import subprocess
import unittest
import json
import sys
import tests.test_registry as test_registry

initial_settings = None

BASIC_TEXT_REPORT_ENTRY = {
            "uniqueId": "basic_text_report_entry",
            "name": "basic_text_report_entry",
            "category": "category",
            "description": "description",
            "displayOrder": 10,
            "readOnly": True,
            "type": "TEXT",
            "table": "sessions",
            "queryText": {
                "textColumns": ["count(*) as session_count"]
            },
            "rendering": {
                "arbitrary1": 1,
                "arbitrary2": True,
                "arbitrary3": "arbitrary3"
            }
        }

BASIC_EVENTS_REPORT_ENTRY = {
            "uniqueId": "basic_events_report_entry",
            "name": "basic_events_report_entry",
            "category": "category",
            "description": "description",
            "displayOrder": 10,
            "readOnly": True,
            "type": "EVENTS",
            "table": "sessions",
            "rendering": {
                "arbitrary1": 1,
                "arbitrary2": True,
                "arbitrary3": "arbitrary3"
            }
        }

BASIC_CATEGORIES_REPORT_ENTRY = {
            "uniqueId": "basic_categories_report_entry",
            "name": "basic_categories_report_entry",
            "category": "category",
            "description": "description",
            "displayOrder": 10,
            "readOnly": True,
            "type": "CATEGORIES",
            "table": "sessions",
            "queryCategories": {
                "categoriesGroupColumn": "client_address",
                "categoriesAggregation": "count(*)"
            },
            "rendering": {
                "arbitrary1": 1,
                "arbitrary2": True,
                "arbitrary3": "arbitrary3"
            }
        }

BASIC_SERIES_REPORT_ENTRY = {
            "uniqueId": "basic_series_report_entry",
            "name": "basic_series_report_entry",
            "category": "category",
            "description": "description",
            "displayOrder": 10,
            "readOnly": True,
            "type": "SERIES",
            "table": "sessions",
            "querySeries": {
                "seriesColumns": ["count(*) as sessions"]
            },
            "rendering": {
                "arbitrary1": 1,
                "arbitrary2": True,
                "arbitrary3": "arbitrary3"
            }
        }


def create_query(report_entry):
    """Creates a query from the specified report_entry"""
    json_string = json.dumps(report_entry)
    cmd = 'curl -m 5 -X POST -s -o - -H "Content-Type: application/json; charset=utf-8" -d \'%s\' "http://localhost:8080/api/reports/create_query"' % json_string
    print(cmd)
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    output = p.stdout.decode()
    if p.returncode != 0:
        return None
    else:
        return int(output)

def get_data(query_id):
    """Gets the data for the specified query ID"""
    cmd = 'curl -m 5 -X GET -s -o - "http://localhost:8080/api/reports/get_data/%s"' % str(query_id)
    print(cmd)
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    output = p.stdout.decode()
    if p.returncode != 0:
        return None
    else:
        return json.loads(output)
    
class ReportsTests(unittest.TestCase):

    @staticmethod
    def moduleName():
        return "settings"

    @staticmethod
    def initialSetUp(self):
        pass

    def setUp(self):
        print()

    def test_000_basic_test(self):
        assert(True)

    def test_010_text_query(self):
        global BASIC_TEXT_REPORT_ENTRY
        query_id = create_query(BASIC_TEXT_REPORT_ENTRY)
        assert(query_id != None)
        results = get_data(query_id)
        assert(results != None)
        assert(results[0] != None)
        assert(results[0]["session_count"] != None)

    def test_011_events_query(self):
        global BASIC_EVENTS_REPORT_ENTRY
        query_id = create_query(BASIC_EVENTS_REPORT_ENTRY)
        assert(query_id != None)
        results = get_data(query_id)
        assert(results != None)
        assert(isinstance(results, list))
        if len(results) > 0:
            # Just check some columns that should never be null
            assert(results[0]["client_address"] != None)
            assert(results[0]["server_address"] != None)
            assert(results[0]["client_port"] != None)
            assert(results[0]["server_port"] != None)

    def test_012_categories_query(self):
        global BASIC_CATEGORIES_REPORT_ENTRY
        query_id = create_query(BASIC_CATEGORIES_REPORT_ENTRY)
        assert(query_id != None)
        results = get_data(query_id)
        assert(results != None)
        assert(isinstance(results, list))
        if len(results) > 0:
            assert(results[0]["client_address"] != None)
            assert(results[0]["value"] != None)

    def test_013_series_query(self):
        global BASIC_SERIES_REPORT_ENTRY
        query_id = create_query(BASIC_SERIES_REPORT_ENTRY)
        assert(query_id != None)
        results = get_data(query_id)
        assert(results != None)
        assert(len(results) > 0)
        assert(results[0]["time_trunc"] != None)
        
    @staticmethod
    def finalTearDown(self):
        pass

test_registry.register_module("reports", ReportsTests)
