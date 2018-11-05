import subprocess
import unittest
import json
import sys
import tests.test_registry as test_registry

initial_settings = None

def create_query(report_entry):
    """Creates a query from the specified report_entry"""
    json_string = json.dumps(report_entry)
    cmd = 'curl -m 5 -X POST -s -o - -H "Content-Type: application/json; charset=utf-8" -d \'%s\' "http://localhost:8080/reports/create_query"' % json_string
    print(cmd)
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    output = p.stdout.decode()
    if p.returncode != 0:
        return None
    else:
        return int(output)

def get_data(query_id):
    """Gets the data for the specified query ID"""
    cmd = 'curl -m 5 -X GET -s -o - "http://localhost:8080/reports/get_data/%s"' % str(query_id)
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

    def test_010_create_query(self):
        report_query = {
            "uniqueId": "abcdefghijkl",
            "name": "create_query",
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
        query_id = create_query(report_query)
        assert(query_id != None)
        results = get_data(query_id)
        assert(results != None)
        assert(results[0] != None)
        assert(results[0]["session_count"] != None)
        
    @staticmethod
    def finalTearDown(self):
        pass

test_registry.register_module("reports", ReportsTests)
