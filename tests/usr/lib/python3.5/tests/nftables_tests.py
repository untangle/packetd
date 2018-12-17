import subprocess
import unittest
import json
import sys
import traceback
import tests.test_registry as test_registry
import sync.nftables_util as nftables_util

class NftablesTests(unittest.TestCase):

    @staticmethod
    def module_name():
        return "nftables_util"

    def setUp(self):
        print()
    
    @staticmethod
    def initial_setup(self):
        pass


# ACTIONS
# ACTIONS
# ACTIONS

    def test_100_action_reject(self):
        """Check action REJECT"""
        action = {"type": "REJECT"}
        str = nftables_util.action_expression(action, "inet")
        print(str)
        assert(str == 'reject')

    def test_101_action_accept(self):
        """Check action ACCEPT"""
        action = {"type": "ACCEPT"}
        str = nftables_util.action_expression(action, "inet")
        print(str)
        assert(str == 'accept')

    def test_102_action_jump(self):
        """Check action JUMP"""
        action = {"type": "JUMP", "chain":"target"}
        str = nftables_util.action_expression(action, "inet")
        print(str)
        assert(str == 'jump target')

    def test_103_action_goto(self):
        """Check action GOTO"""
        action = {"type": "GOTO", "chain":"target"}
        str = nftables_util.action_expression(action, "inet")
        print(str)
        assert(str == 'goto target')

    def test_103_action_return(self):
        """Check action GOTO"""
        action = {"type": "RETURN"}
        str = nftables_util.action_expression(action, "inet")
        print(str)
        assert(str == 'return')
        
# RULES
# RULES
# RULES

    def test_200_rule_not_enabled(self):
        """Check that a rule that is not enabled returns None"""
        rule = {
            "description": "description",
            "ruleId": 1,
            "enabled": False,
            "conditions": [{
                "type": "IP_PROTOCOL",
                "op": "==",
                "value": "tcp"
            }],
            "action": {
                "type": "ACCEPT"
            }
        }
        rule_str = nftables_util.rule_cmd(rule, "inet", "forward", "forward-filter")
        print(rule_str)
        assert(rule_str == None)

    def test_201_rule_basic(self):
        """Check action a basic rule"""
        rule = {
            "description": "description",
            "ruleId": 1,
            "enabled": True,
            "conditions": [{
                "type": "IP_PROTOCOL",
                "op": "==",
                "value": "tcp"
            }],
            "action": {
                "type": "ACCEPT"
            }
        }
        exp_str = nftables_util.rule_expression(rule, "inet")
        print(exp_str)
        rule_str = nftables_util.rule_cmd(rule, "inet", "forward", "forward-filter")
        print(rule_str)
        assert(exp_str == "ip protocol 'tcp' accept")
        assert(rule_str == "nft add rule inet forward forward-filter ip protocol 'tcp' accept")
        


    @staticmethod
    def final_tear_down(self):
        pass


def create_conditions_test(conditions_json, expected_str):
    def do_test(self):
        try:
            str = nftables_util.conditions_expression(conditions_json,"inet")
        except:
            traceback.print_exc()
            traceback.print_stack()
            if expected_str == None:
                assert True
                return
            else:
                assert False
                return
        print("Actual   : " + str)
        print("Expected : " + expected_str)
        assert str == expected_str
    return do_test

conditions_tests = [
    [[{"value":"foo","op":"=="}], None],

    [[{"type": "IP_PROTOCOL","op":"=="}], None],
    [[{"type": "IP_PROTOCOL","op":"==","value": "tcp,udp"}], "ip protocol '{tcp,udp}'"],
    [[{"type": "IP_PROTOCOL","op":"!=","value": "tcp,udp"}], "ip protocol != '{tcp,udp}'"],
    [[{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "ip protocol 'tcp'"],
    [[{"type": "IP_PROTOCOL","op":"==","value": "TCP"}], "ip protocol 'tcp'"],
    [[{"type": "IP_PROTOCOL","op":"!=","value": "tcp"}], "ip protocol != 'tcp'"],

    [[{"type": "SOURCE_INTERFACE_NAME","op":"==","value": "lo"}], "iifname 'lo'"],
    [[{"type": "SOURCE_INTERFACE_NAME","op":"!=","value": "lo"}], "iifname != 'lo'"],
    [[{"type": "DESTINATION_INTERFACE_NAME","op":"==","value": "lo"}], "oifname 'lo'"],
    [[{"type": "DESTINATION_INTERFACE_NAME","op":"!=","value": "lo"}], "oifname != 'lo'"],

    [[{"type": "SOURCE_ADDRESS","op":"==","value": "1.2.3.4"}], "ip saddr '1.2.3.4'"],
    [[{"type": "SOURCE_ADDRESS","op":"!=","value": "1.2.3.4"}], "ip saddr != '1.2.3.4'"],
    [[{"type": "SOURCE_ADDRESS","op":"==","value": "1.2.3.4/24"}], "ip saddr '1.2.3.4/24'"],
    [[{"type": "SOURCE_ADDRESS","op":"!=","value": "1.2.3.4/24"}], "ip saddr != '1.2.3.4/24'"],
    [[{"type": "SOURCE_ADDRESS","op":"==","value": "1.2.3.4,1.2.3.5/24"}], "ip saddr '{1.2.3.4,1.2.3.5/24}'"],
    [[{"type": "SOURCE_ADDRESS","op":"!=","value": "1.2.3.4,1.2.3.5/24"}], "ip saddr != '{1.2.3.4,1.2.3.5/24}'"],

    [[{"type": "SOURCE_ADDRESS_V6","op":"==","value": "fe80::1"}], "ip6 saddr 'fe80::1'"],
    [[{"type": "SOURCE_ADDRESS_V6","op":"!=","value": "fe80::1"}], "ip6 saddr != 'fe80::1'"],

    [[{"type": "DESTINATION_ADDRESS","op":"==","value": "1.2.3.4"}], "ip daddr '1.2.3.4'"],
    [[{"type": "DESTINATION_ADDRESS","op":"!=","value": "1.2.3.4"}], "ip daddr != '1.2.3.4'"],
    [[{"type": "DESTINATION_ADDRESS","op":"==","value": "1.2.3.4/24"}], "ip daddr '1.2.3.4/24'"],
    [[{"type": "DESTINATION_ADDRESS","op":"!=","value": "1.2.3.4/24"}], "ip daddr != '1.2.3.4/24'"],
    [[{"type": "DESTINATION_ADDRESS","op":"==","value": "1.2.3.4,1.2.3.5/24"}], "ip daddr '{1.2.3.4,1.2.3.5/24}'"],
    [[{"type": "DESTINATION_ADDRESS","op":"!=","value": "1.2.3.4,1.2.3.5/24"}], "ip daddr != '{1.2.3.4,1.2.3.5/24}'"],

    [[{"type": "DESTINATION_ADDRESS_V6","op":"==","value": "fe80::1"}], "ip6 daddr 'fe80::1'"],
    [[{"type": "DESTINATION_ADDRESS_V6","op":"!=","value": "fe80::1"}], "ip6 daddr != 'fe80::1'"],

    [[{"type": "SOURCE_ADDRESS_TYPE","op":"==","value": "local"}], "fib saddr type 'local'"],
    [[{"type": "SOURCE_ADDRESS_TYPE","op":"!=","value": "local"}], "fib saddr type != 'local'"],
    [[{"type": "SOURCE_ADDRESS_TYPE","op":"==","value": "unicast"}], "fib saddr type 'unicast'"],
    [[{"type": "SOURCE_ADDRESS_TYPE","op":"==","value": "invalid_type"}], None],
    [[{"type": "DESTINATION_ADDRESS_TYPE","op":"==","value": "local"}], "fib daddr type 'local'"],
    [[{"type": "DESTINATION_ADDRESS_TYPE","op":"!=","value": "local"}], "fib daddr type != 'local'"],
    [[{"type": "DESTINATION_ADDRESS_TYPE","op":"==","value": "unicast"}], "fib daddr type 'unicast'"],
    [[{"type": "DESTINATION_ADDRESS_TYPE","op":"==","value": "invalid_type"}], None],

    [[{"type": "SOURCE_PORT","op":"==","value": "1234"}], None],
    [[{"type": "SOURCE_PORT","op":"==","value": "1234"}], None],
    [[{"type": "SOURCE_PORT","op":"==","value": "1234"}], None],
    [[{"type": "SOURCE_PORT","op":"==","value": "1234"},{"type": "IP_PROTOCOL","op":"==","value": 6}], "tcp sport '1234' ip protocol '6'"],
    [[{"type": "SOURCE_PORT","op":"==","value": "1234"},{"type": "IP_PROTOCOL","op":"==","value": "6"}], "tcp sport '1234' ip protocol '6'"],
    [[{"type": "SOURCE_PORT","op":"==","value": "1234"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp sport '1234' ip protocol 'tcp'"],
    [[{"type": "SOURCE_PORT","op":"!=","value": "1234"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp sport != '1234' ip protocol 'tcp'"],
    [[{"type": "SOURCE_PORT","op":"==","value": "1235-1236"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp sport '1235-1236' ip protocol 'tcp'"],
    [[{"type": "SOURCE_PORT","op":"!=","value": "1235-1236"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp sport != '1235-1236' ip protocol 'tcp'"],
    [[{"type": "SOURCE_PORT","op":"==","value": "1234,1235-1236"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp sport '{1234,1235-1236}' ip protocol 'tcp'"],
    [[{"type": "SOURCE_PORT","op":"!=","value": "1234,1235-1236"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp sport != '{1234,1235-1236}' ip protocol 'tcp'"],

    [[{"type": "DESTINATION_PORT","op":"==","value": "1234"}], None],
    [[{"type": "DESTINATION_PORT","op":"==","value": "1234"}], None],
    [[{"type": "DESTINATION_PORT","op":"==","value": "1234"}], None],
    [[{"type": "DESTINATION_PORT","op":"==","value": "1234"},{"type": "IP_PROTOCOL","op":"==","value": 6}], "tcp dport '1234' ip protocol '6'"],
    [[{"type": "DESTINATION_PORT","op":"==","value": "1234"},{"type": "IP_PROTOCOL","op":"==","value": "6"}], "tcp dport '1234' ip protocol '6'"],
    [[{"type": "DESTINATION_PORT","op":"==","value": "1234"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp dport '1234' ip protocol 'tcp'"],
    [[{"type": "DESTINATION_PORT","op":"!=","value": "1234"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp dport != '1234' ip protocol 'tcp'"],
    [[{"type": "DESTINATION_PORT","op":"==","value": "1235-1236"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp dport '1235-1236' ip protocol 'tcp'"],
    [[{"type": "DESTINATION_PORT","op":"!=","value": "1235-1236"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp dport != '1235-1236' ip protocol 'tcp'"],
    [[{"type": "DESTINATION_PORT","op":"==","value": "1234,1235-1236"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp dport '{1234,1235-1236}' ip protocol 'tcp'"],
    [[{"type": "DESTINATION_PORT","op":"!=","value": "1234,1235-1236"},{"type": "IP_PROTOCOL","op":"==","value": "tcp"}], "tcp dport != '{1234,1235-1236}' ip protocol 'tcp'"],

    [[{"type": "SOURCE_INTERFACE_ZONE","op":"==","value": "1"}], "mark and 0x000000ff '1'"],
    [[{"type": "SOURCE_INTERFACE_ZONE","op":"!=","value": "1"}], "mark and 0x000000ff != '1'"],
    [[{"type": "SOURCE_INTERFACE_ZONE","op":"==","value": "1,2"}], "mark and 0x000000ff '{1,2}'"],
    [[{"type": "SOURCE_INTERFACE_ZONE","op":"!=","value": "1,2"}], "mark and 0x000000ff != '{1,2}'"],
    [[{"type": "SOURCE_INTERFACE_ZONE","op":"==","value": "wan"}], "mark and 0x01000000 != '0'"],
    [[{"type": "SOURCE_INTERFACE_ZONE","op":"==","value": "non_wan"}], "mark and 0x01000000 == '0'"],
    [[{"type": "SOURCE_INTERFACE_ZONE","op":"==","value": "1,wan"}], None],

    [[{"type": "DESTINATION_INTERFACE_ZONE","op":"==","value": "1"}], "mark and 0x0000ff00 '1'"],
    [[{"type": "DESTINATION_INTERFACE_ZONE","op":"!=","value": "1"}], "mark and 0x0000ff00 != '1'"],
    [[{"type": "DESTINATION_INTERFACE_ZONE","op":"==","value": "1,2"}], "mark and 0x0000ff00 '{1,2}'"],
    [[{"type": "DESTINATION_INTERFACE_ZONE","op":"!=","value": "1,2"}], "mark and 0x0000ff00 != '{1,2}'"],
    [[{"type": "DESTINATION_INTERFACE_ZONE","op":"==","value": "wan"}], "mark and 0x02000000 != '0'"],
    [[{"type": "DESTINATION_INTERFACE_ZONE","op":"==","value": "non_wan"}], "mark and 0x02000000 == '0'"],
    [[{"type": "DESTINATION_INTERFACE_ZONE","op":"==","value": "1,wan"}], None],

    [[{"type": "CLIENT_INTERFACE_ZONE","op":"==","value": "1"}], "ct mark and 0x000000ff '1'"],
    [[{"type": "CLIENT_INTERFACE_ZONE","op":"!=","value": "1"}], "ct mark and 0x000000ff != '1'"],
    [[{"type": "CLIENT_INTERFACE_ZONE","op":"==","value": "1,2"}], "ct mark and 0x000000ff '{1,2}'"],
    [[{"type": "CLIENT_INTERFACE_ZONE","op":"!=","value": "1,2"}], "ct mark and 0x000000ff != '{1,2}'"],
    [[{"type": "CLIENT_INTERFACE_ZONE","op":"==","value": "wan"}], "ct mark and 0x01000000 != '0'"],
    [[{"type": "CLIENT_INTERFACE_ZONE","op":"==","value": "non_wan"}], "ct mark and 0x01000000 == '0'"],
    [[{"type": "CLIENT_INTERFACE_ZONE","op":"==","value": "1,wan"}], None],

    [[{"type": "SERVER_INTERFACE_ZONE","op":"==","value": "1"}], "ct mark and 0x0000ff00 '1'"],
    [[{"type": "SERVER_INTERFACE_ZONE","op":"!=","value": "1"}], "ct mark and 0x0000ff00 != '1'"],
    [[{"type": "SERVER_INTERFACE_ZONE","op":"==","value": "1,2"}], "ct mark and 0x0000ff00 '{1,2}'"],
    [[{"type": "SERVER_INTERFACE_ZONE","op":"!=","value": "1,2"}], "ct mark and 0x0000ff00 != '{1,2}'"],
    [[{"type": "SERVER_INTERFACE_ZONE","op":"==","value": "wan"}], "ct mark and 0x02000000 != '0'"],
    [[{"type": "SERVER_INTERFACE_ZONE","op":"==","value": "non_wan"}], "ct mark and 0x02000000 == '0'"],
    [[{"type": "SERVER_INTERFACE_ZONE","op":"==","value": "1,wan"}], None],

    [[{"type": "CLIENT_PORT","op":"==","value": "1234"}], "dict session ct id client_port int '1234'"],
    [[{"type": "CLIENT_PORT","op":"!=","value": "1234"}], "dict session ct id client_port int != '1234'"],
    [[{"type": "CLIENT_PORT","op":"==","value": "1235-1236"}], "dict session ct id client_port int '1235-1236'"],
    [[{"type": "CLIENT_PORT","op":"!=","value": "1235-1236"}], "dict session ct id client_port int != '1235-1236'"],
    [[{"type": "CLIENT_PORT","op":"==","value": "1234,1235-1236"}], "dict session ct id client_port int '{1234,1235-1236}'"],
    [[{"type": "CLIENT_PORT","op":"!=","value": "1234,1235-1236"}], "dict session ct id client_port int != '{1234,1235-1236}'"],

    [[{"type": "SERVER_PORT","op":"==","value": "1234"}], "dict session ct id server_port int '1234'"],
    [[{"type": "SERVER_PORT","op":"!=","value": "1234"}], "dict session ct id server_port int != '1234'"],
    [[{"type": "SERVER_PORT","op":"==","value": "1235-1236"}], "dict session ct id server_port int '1235-1236'"],
    [[{"type": "SERVER_PORT","op":"!=","value": "1235-1236"}], "dict session ct id server_port int != '1235-1236'"],
    [[{"type": "SERVER_PORT","op":"==","value": "1234,1235-1236"}], "dict session ct id server_port int '{1234,1235-1236}'"],
    [[{"type": "SERVER_PORT","op":"!=","value": "1234,1235-1236"}], "dict session ct id server_port int != '{1234,1235-1236}'"],

    [[{"type": "LOCAL_PORT","op":"==","value": "1234"}], "dict session ct id local_port int '1234'"],
    [[{"type": "LOCAL_PORT","op":"!=","value": "1234"}], "dict session ct id local_port int != '1234'"],
    [[{"type": "LOCAL_PORT","op":"==","value": "1235-1236"}], "dict session ct id local_port int '1235-1236'"],
    [[{"type": "LOCAL_PORT","op":"!=","value": "1235-1236"}], "dict session ct id local_port int != '1235-1236'"],
    [[{"type": "LOCAL_PORT","op":"==","value": "1234,1235-1236"}], "dict session ct id local_port int '{1234,1235-1236}'"],
    [[{"type": "LOCAL_PORT","op":"!=","value": "1234,1235-1236"}], "dict session ct id local_port int != '{1234,1235-1236}'"],

    [[{"type": "REMOTE_PORT","op":"==","value": "1234"}], "dict session ct id remote_port int '1234'"],
    [[{"type": "REMOTE_PORT","op":"!=","value": "1234"}], "dict session ct id remote_port int != '1234'"],
    [[{"type": "REMOTE_PORT","op":"==","value": "1235-1236"}], "dict session ct id remote_port int '1235-1236'"],
    [[{"type": "REMOTE_PORT","op":"!=","value": "1235-1236"}], "dict session ct id remote_port int != '1235-1236'"],
    [[{"type": "REMOTE_PORT","op":"==","value": "1234,1235-1236"}], "dict session ct id remote_port int '{1234,1235-1236}'"],
    [[{"type": "REMOTE_PORT","op":"!=","value": "1234,1235-1236"}], "dict session ct id remote_port int != '{1234,1235-1236}'"],

    [[{"type": "CLIENT_ADDRESS","op":"==","value": "1.2.3.4"}], "dict session ct id client_address ipv4_addr '1.2.3.4'"],
    [[{"type": "CLIENT_ADDRESS","op":"!=","value": "1.2.3.4"}], "dict session ct id client_address ipv4_addr != '1.2.3.4'"],
    [[{"type": "CLIENT_ADDRESS","op":"==","value": "1.2.3.4/24"}], "dict session ct id client_address ipv4_addr '1.2.3.4/24'"],
    [[{"type": "CLIENT_ADDRESS","op":"!=","value": "1.2.3.4/24"}], "dict session ct id client_address ipv4_addr != '1.2.3.4/24'"],
    [[{"type": "CLIENT_ADDRESS","op":"==","value": "1.2.3.4,1.2.3.5/24"}], "dict session ct id client_address ipv4_addr '{1.2.3.4,1.2.3.5/24}'"],
    [[{"type": "CLIENT_ADDRESS","op":"!=","value": "1.2.3.4,1.2.3.5/24"}], "dict session ct id client_address ipv4_addr != '{1.2.3.4,1.2.3.5/24}'"],

    [[{"type": "CLIENT_ADDRESS_V6","op":"==","value": "fe80::1"}], "dict session ct id client_address ipv6_addr 'fe80::1'"],
    [[{"type": "CLIENT_ADDRESS_V6","op":"!=","value": "fe80::1"}], "dict session ct id client_address ipv6_addr != 'fe80::1'"],

    [[{"type": "SERVER_ADDRESS","op":"==","value": "1.2.3.4"}], "dict session ct id server_address ipv4_addr '1.2.3.4'"],
    [[{"type": "SERVER_ADDRESS","op":"!=","value": "1.2.3.4"}], "dict session ct id server_address ipv4_addr != '1.2.3.4'"],
    [[{"type": "SERVER_ADDRESS","op":"==","value": "1.2.3.4/24"}], "dict session ct id server_address ipv4_addr '1.2.3.4/24'"],
    [[{"type": "SERVER_ADDRESS","op":"!=","value": "1.2.3.4/24"}], "dict session ct id server_address ipv4_addr != '1.2.3.4/24'"],
    [[{"type": "SERVER_ADDRESS","op":"==","value": "1.2.3.4,1.2.3.5/24"}], "dict session ct id server_address ipv4_addr '{1.2.3.4,1.2.3.5/24}'"],
    [[{"type": "SERVER_ADDRESS","op":"!=","value": "1.2.3.4,1.2.3.5/24"}], "dict session ct id server_address ipv4_addr != '{1.2.3.4,1.2.3.5/24}'"],

    [[{"type": "SERVER_ADDRESS_V6","op":"==","value": "fe80::1"}], "dict session ct id server_address ipv6_addr 'fe80::1'"],
    [[{"type": "SERVER_ADDRESS_V6","op":"!=","value": "fe80::1"}], "dict session ct id server_address ipv6_addr != 'fe80::1'"],

    [[{"type": "LOCAL_ADDRESS","op":"==","value": "1.2.3.4"}], "dict session ct id local_address ipv4_addr '1.2.3.4'"],
    [[{"type": "LOCAL_ADDRESS","op":"!=","value": "1.2.3.4"}], "dict session ct id local_address ipv4_addr != '1.2.3.4'"],
    [[{"type": "LOCAL_ADDRESS","op":"==","value": "1.2.3.4/24"}], "dict session ct id local_address ipv4_addr '1.2.3.4/24'"],
    [[{"type": "LOCAL_ADDRESS","op":"!=","value": "1.2.3.4/24"}], "dict session ct id local_address ipv4_addr != '1.2.3.4/24'"],
    [[{"type": "LOCAL_ADDRESS","op":"==","value": "1.2.3.4,1.2.3.5/24"}], "dict session ct id local_address ipv4_addr '{1.2.3.4,1.2.3.5/24}'"],
    [[{"type": "LOCAL_ADDRESS","op":"!=","value": "1.2.3.4,1.2.3.5/24"}], "dict session ct id local_address ipv4_addr != '{1.2.3.4,1.2.3.5/24}'"],

    [[{"type": "LOCAL_ADDRESS_V6","op":"==","value": "fe80::1"}], "dict session ct id local_address ipv6_addr 'fe80::1'"],
    [[{"type": "LOCAL_ADDRESS_V6","op":"!=","value": "fe80::1"}], "dict session ct id local_address ipv6_addr != 'fe80::1'"],

    [[{"type": "REMOTE_ADDRESS","op":"==","value": "1.2.3.4"}], "dict session ct id remote_address ipv4_addr '1.2.3.4'"],
    [[{"type": "REMOTE_ADDRESS","op":"!=","value": "1.2.3.4"}], "dict session ct id remote_address ipv4_addr != '1.2.3.4'"],
    [[{"type": "REMOTE_ADDRESS","op":"==","value": "1.2.3.4/24"}], "dict session ct id remote_address ipv4_addr '1.2.3.4/24'"],
    [[{"type": "REMOTE_ADDRESS","op":"!=","value": "1.2.3.4/24"}], "dict session ct id remote_address ipv4_addr != '1.2.3.4/24'"],
    [[{"type": "REMOTE_ADDRESS","op":"==","value": "1.2.3.4,1.2.3.5/24"}], "dict session ct id remote_address ipv4_addr '{1.2.3.4,1.2.3.5/24}'"],
    [[{"type": "REMOTE_ADDRESS","op":"!=","value": "1.2.3.4,1.2.3.5/24"}], "dict session ct id remote_address ipv4_addr != '{1.2.3.4,1.2.3.5/24}'"],

    [[{"type": "REMOTE_ADDRESS_V6","op":"==","value": "fe80::1"}], "dict session ct id remote_address ipv6_addr 'fe80::1'"],
    [[{"type": "REMOTE_ADDRESS_V6","op":"!=","value": "fe80::1"}], "dict session ct id remote_address ipv6_addr != 'fe80::1'"],

    [[{"type": "CLIENT_HOSTNAME","op":"==","value": "hostname"}], "dict session ct id client_hostname long_string 'hostname'"],
    [[{"type": "CLIENT_HOSTNAME","op":"!=","value": "hostname"}], "dict session ct id client_hostname long_string != 'hostname'"],
    [[{"type": "CLIENT_HOSTNAME","op":"==","value": "hostname,hostname2"}], "dict session ct id client_hostname long_string '{hostname,hostname2}'"],
    [[{"type": "CLIENT_HOSTNAME","op":"!=","value": "hostname,hostname2"}], "dict session ct id client_hostname long_string != '{hostname,hostname2}'"],

    [[{"type": "SERVER_HOSTNAME","op":"==","value": "hostname"}], "dict session ct id server_hostname long_string 'hostname'"],
    [[{"type": "SERVER_HOSTNAME","op":"!=","value": "hostname"}], "dict session ct id server_hostname long_string != 'hostname'"],
    [[{"type": "SERVER_HOSTNAME","op":"==","value": "hostname,hostname2"}], "dict session ct id server_hostname long_string '{hostname,hostname2}'"],
    [[{"type": "SERVER_HOSTNAME","op":"!=","value": "hostname,hostname2"}], "dict session ct id server_hostname long_string != '{hostname,hostname2}'"],

    [[{"type": "LOCAL_HOSTNAME","op":"==","value": "hostname"}], "dict session ct id local_hostname long_string 'hostname'"],
    [[{"type": "LOCAL_HOSTNAME","op":"!=","value": "hostname"}], "dict session ct id local_hostname long_string != 'hostname'"],
    [[{"type": "LOCAL_HOSTNAME","op":"==","value": "hostname,hostname2"}], "dict session ct id local_hostname long_string '{hostname,hostname2}'"],
    [[{"type": "LOCAL_HOSTNAME","op":"!=","value": "hostname,hostname2"}], "dict session ct id local_hostname long_string != '{hostname,hostname2}'"],

    [[{"type": "REMOTE_HOSTNAME","op":"==","value": "hostname"}], "dict session ct id remote_hostname long_string 'hostname'"],
    [[{"type": "REMOTE_HOSTNAME","op":"!=","value": "hostname"}], "dict session ct id remote_hostname long_string != 'hostname'"],
    [[{"type": "REMOTE_HOSTNAME","op":"==","value": "hostname,hostname2"}], "dict session ct id remote_hostname long_string '{hostname,hostname2}'"],
    [[{"type": "REMOTE_HOSTNAME","op":"!=","value": "hostname,hostname2"}], "dict session ct id remote_hostname long_string != '{hostname,hostname2}'"],

    [[{"type": "CLIENT_USERNAME","op":"==","value": "username"}], "dict session ct id client_username long_string 'username'"],
    [[{"type": "CLIENT_USERNAME","op":"!=","value": "username"}], "dict session ct id client_username long_string != 'username'"],
    [[{"type": "CLIENT_USERNAME","op":"==","value": "username,username2"}], "dict session ct id client_username long_string '{username,username2}'"],
    [[{"type": "CLIENT_USERNAME","op":"!=","value": "username,username2"}], "dict session ct id client_username long_string != '{username,username2}'"],

    [[{"type": "SERVER_USERNAME","op":"==","value": "username"}], "dict session ct id server_username long_string 'username'"],
    [[{"type": "SERVER_USERNAME","op":"!=","value": "username"}], "dict session ct id server_username long_string != 'username'"],
    [[{"type": "SERVER_USERNAME","op":"==","value": "username,username2"}], "dict session ct id server_username long_string '{username,username2}'"],
    [[{"type": "SERVER_USERNAME","op":"!=","value": "username,username2"}], "dict session ct id server_username long_string != '{username,username2}'"],

    [[{"type": "LOCAL_USERNAME","op":"==","value": "username"}], "dict session ct id local_username long_string 'username'"],
    [[{"type": "LOCAL_USERNAME","op":"!=","value": "username"}], "dict session ct id local_username long_string != 'username'"],
    [[{"type": "LOCAL_USERNAME","op":"==","value": "username,username2"}], "dict session ct id local_username long_string '{username,username2}'"],
    [[{"type": "LOCAL_USERNAME","op":"!=","value": "username,username2"}], "dict session ct id local_username long_string != '{username,username2}'"],

    [[{"type": "REMOTE_USERNAME","op":"==","value": "username"}], "dict session ct id remote_username long_string 'username'"],
    [[{"type": "REMOTE_USERNAME","op":"!=","value": "username"}], "dict session ct id remote_username long_string != 'username'"],
    [[{"type": "REMOTE_USERNAME","op":"==","value": "username,username2"}], "dict session ct id remote_username long_string '{username,username2}'"],
    [[{"type": "REMOTE_USERNAME","op":"!=","value": "username,username2"}], "dict session ct id remote_username long_string != '{username,username2}'"],
]

for i, obj in enumerate(conditions_tests):
    method = create_conditions_test(obj[0],obj[1])
    first_condition = obj[0][0]
    method.__name__="test_"+str(500+i)+"_"+str(first_condition.get('type')).lower()
    setattr(NftablesTests, method.__name__, method)
    
test_registry.register_module("nftables_util", NftablesTests)
