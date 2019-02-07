"""Reports tests"""
# pylint: disable=no-self-use
import subprocess
import unittest
import json
import runtests.test_registry as test_registry


ONE_CONDITION = {
    "conditions": [{
        "column": "ip_protocol",
        "operator": "EQ",
        "value": "17"
    }]
}

TWO_CONDITION = {
    "conditions": [{
        "column": "ip_protocol",
        "operator": "EQ",
        "value": "17"
    }, {
        "column": "client_bytes",
        "operator": "GT",
        "value": "0"
    }]
}

TIME_CONDITION = {
    "conditions": [{
        "column": "time_stamp",
        "operator": "GT",
        "value": 1544133600000
    }]
}

TIME_USER_CONDITION = {
    "userConditions": [{
        "column": "time_stamp",
        "operator": "GT",
        "value": 1544133600000
    }]
}

TIME_CONDITION2 = {
    "conditions": [{
        "column": "time_stamp",
        "operator": "GT",
        "value": "1544133600000"
    }]
}

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
        "columns": ["count(*) as session_count"]
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
        "groupColumn": "client_address",
        "aggregationFunction": "count",
        "aggregationValue": "*"
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
        "columns": ["count(*) as sessions"]
    },
    "rendering": {
        "arbitrary1": 1,
        "arbitrary2": True,
        "arbitrary3": "arbitrary3"
    }
}

BASIC_CATEGORIES_SERIES_REPORT_ENTRY = {
    "uniqueId": "basic_series_report_entry",
    "name": "basic_series_report_entry",
    "category": "category",
    "description": "description",
    "displayOrder": 10,
    "readOnly": True,
    "type": "CATEGORIES_SERIES",
    "table": "sessions",
    "queryCategories": {
        "groupColumn": "client_address",
        "aggregationFunction": "count",
        "aggregationValue": "1",
        "limit": 5
    },
    "rendering": {
        "arbitrary1": 1,
        "arbitrary2": True,
        "arbitrary3": "arbitrary3"
    }
}

JOIN_REPORT_ENTRY = {
    "name": "Top Application by Bandwidth",
    "category": "Sessions",
    "description": "The application sorted by sum of bytes transferred",
    "displayOrder": 20,
    "type": "CATEGORIES",
    "table": "sessions join session_stats using (session_id)",
    "columnDisambiguation": [{
        "columnName": "time_stamp",
        "newColumnName": "session_stats.time_stamp"
    }],
    "queryCategories": {
        "groupColumn": "application_name",
        "aggregationFunction": "sum",
        "aggregationValue": "bytes"
    },
    "rendering": {
        "type": "pie",
        "donutInnerSize": 50,
        "3dEnabled": True
    }
}

def merge(dict1, dict2):
    """Merge the entries from two dictionaries and return a new dictionary"""
    res = {**dict1, **dict2}
    return res

def create_query(report_entry):
    """Creates a query from the specified report_entry"""
    json_string = json.dumps(report_entry)
    cmd = 'curl -m 5 -X POST -s -o - -H "Content-Type: application/json; charset=utf-8" -d \'%s\' "http://localhost/api/reports/create_query"' % json_string
    print(cmd)
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    output = p.stdout.decode()
    if p.returncode != 0:
        return None
    else:
        try:
            return int(output)
        except Exception as e:
            print("OUTPUT: " + output)
            raise e

def get_data(query_id):
    """Gets the data for the specified query ID"""
    cmd = 'curl -m 5 -X GET -s -o - "http://localhost/api/reports/get_data/%s"' % str(query_id)
    print(cmd)
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    output = p.stdout.decode()
    if p.returncode != 0:
        return None
    else:
        return json.loads(output)

def close_query(query_id):
    """Closes the specified query ID"""
    cmd = 'curl -m 5 -X POST -s -o - "http://localhost/api/reports/close_query/%s"' % str(query_id)
    print(cmd)
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    output = p.stdout.decode()
    if p.returncode != 0:
        return None
    else:
        return output

class ReportsTests(unittest.TestCase):
    """ReportsTests"""

    @staticmethod
    def module_name():
        """module_name unittest method"""
        return "reports"

    def initial_setup(self):
        """initial_setup unittest method"""
        pass

    def setUp(self):
        """setUp unittest method"""
        print()

    def test_000_basic_test(self):
        """Basic test"""
        assert True

    def test_010_text_query(self):
        """Tests TEXT query"""
        report_entry = BASIC_TEXT_REPORT_ENTRY
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert results[0] != None
        assert results[0]["session_count"] != None

    def test_011_text_query_condition1(self):
        """Tests TEXT query with condition"""
        report_entry = merge(BASIC_TEXT_REPORT_ENTRY, TWO_CONDITION)
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert results[0] != None
        assert results[0]["session_count"] != None

    def test_020_events_query(self):
        """Tests EVENTS query"""
        report_entry = BASIC_EVENTS_REPORT_ENTRY
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert isinstance(results, list)
        if len(results) > 0:
            # Just check some columns that should never be null
            assert results[0]["client_address"] != None
            assert results[0]["server_address"] != None
            assert results[0]["client_port"] != None
            assert results[0]["server_port"] != None

    def test_021_events_query_condition1(self):
        """Tests EVENTS query with condition"""
        report_entry = merge(BASIC_EVENTS_REPORT_ENTRY, ONE_CONDITION)
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert isinstance(results, list)
        if len(results) > 0:
            # Just check some columns that should never be null
            assert results[0]["client_address"] != None
            assert results[0]["server_address"] != None
            assert results[0]["client_port"] != None
            assert results[0]["server_port"] != None

    def test_030_categories_query(self):
        """Tests CATEGORIES query"""
        report_entry = BASIC_CATEGORIES_REPORT_ENTRY
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert isinstance(results, list)
        print(results)
        if len(results) > 0:
            assert results[0]["client_address"] != None
            assert results[0]["value"] != None

    def test_031_categories_query_condition1(self):
        """Tests CATEGORIES query with condition"""
        report_entry = merge(BASIC_CATEGORIES_REPORT_ENTRY, ONE_CONDITION)
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert isinstance(results, list)
        if len(results) > 0:
            assert results[0]["client_address"] != None
            assert results[0]["value"] != None

    def test_040_series_query(self):
        """Tests SERIES query"""
        report_entry = BASIC_SERIES_REPORT_ENTRY
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert len(results) > 0
        assert results[0]["time_trunc"] != None

    def test_041_series_query_condition1(self):
        """Tests SERIES query with condition"""
        report_entry = merge(BASIC_SERIES_REPORT_ENTRY, ONE_CONDITION)
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert len(results) > 0
        assert results[0]["time_trunc"] != None

    def test_042_series_query_condition_time(self):
        """Tests SERIES query with a time condition"""
        report_entry = merge(BASIC_SERIES_REPORT_ENTRY, TIME_CONDITION)
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert len(results) > 0
        assert results[0]["time_trunc"] != None

    def test_043_series_query_condition_time2(self):
        """Tests SERIES query with a time condition as a string"""
        report_entry = merge(BASIC_SERIES_REPORT_ENTRY, TIME_CONDITION2)
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert len(results) > 0
        assert results[0]["time_trunc"] != None

    def test_044_series_query_condition_user_condition(self):
        """Tests SERIES query with a time condition"""
        report_entry = merge(BASIC_SERIES_REPORT_ENTRY, TIME_USER_CONDITION)
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert len(results) > 0
        assert results[0]["time_trunc"] != None

    def test_050_categories_series_query(self):
        """Tests CATEGORY_SERIES query"""
        report_entry = BASIC_CATEGORIES_SERIES_REPORT_ENTRY
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert isinstance(results, list)
        assert len(results) > 0
        result = results[0]
        assert result != None
        assert result.get('time_trunc') != None

    def test_051_categories_series_query_condition1(self):
        """Tests CATEGORY_SERIES query with condition"""
        report_entry = merge(BASIC_CATEGORIES_SERIES_REPORT_ENTRY, ONE_CONDITION)
        query_id = create_query(report_entry)
        assert query_id != None
        results = get_data(query_id)
        close_query(query_id)
        assert results != None
        assert isinstance(results, list)
        assert len(results) > 0
        result = results[0]
        assert result != None
        assert result.get('time_trunc') != None

    def test_060_join_query(self):
        """Tests a report that uses a join in the table"""
        query_id = create_query(JOIN_REPORT_ENTRY)
        assert query_id != None
        results = get_data(query_id)
        print(results)
        close_query(query_id)
        assert results != None
        assert isinstance(results, list)
        assert len(results) > 0
        result = results[0]
        assert result != None
        if len(results) > 0:
            assert "application_name" in results[0]
            assert "value" in results[0]

    def final_tear_down(self):
        """final_tear_down unittest method"""
        pass

test_registry.register_module("reports", ReportsTests)
