import subprocess
import unittest
import json
import sys
import tests.test_registry as test_registry
import sync.nftables_util as nftables_util

class NftablesTests(unittest.TestCase):

    @staticmethod
    def moduleName():
        return "nftables_util"

    def setUp(self):
        print()
        pass
    
    @staticmethod
    def initialSetUp(self):
        pass

    def test_001_condition_no_type_invalid(self):
        """Check that a condition with no type throws an exception"""
        condition = {"value":"foo","op":"IS"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

    def test_001_condition_no_value_invalid(self):
        """Check that a condition with no value throws an exception"""
        condition = {"type":"IP_PROTOCOL","op":"IS"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

    def test_010_condition_ip_protocol(self):
        """Check IP_PROTOCOL is tcp"""
        condition = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip protocol tcp')

    def test_010_condition_ip_protocol_capital(self):
        """Check IP_PROTOCOL is TCP"""
        condition = {"type": "IP_PROTOCOL","op":"IS","value": "TCP"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip protocol tcp')

    def test_010_condition_ip_protocol_invert(self):
        """Check IP_PROTOCOL is not tcp"""
        condition = {"type": "IP_PROTOCOL","op":"IS_NOT","value": "tcp"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip protocol != tcp')
        
    def test_010_condition_ip_protocol_invalid(self):
        """Check IP_PROTOCOL is xxx is invalid"""
        condition = {"type": "IP_PROTOCOL","op":"IS","value": "xxx"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

    def test_010_condition_ip_protocol_multiple(self):
        """Check IP_PROTOCOL is tcp,udp"""
        condition = {"type": "IP_PROTOCOL","op":"IS","value": "tcp,udp"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip protocol "{tcp,udp}"')

    def test_010_condition_ip_protocol_multiple_invert(self):
        """Check IP_PROTOCOL is not tcp,udp"""
        condition = {"type": "IP_PROTOCOL","op":"IS_NOT","value": "tcp,udp"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip protocol != "{tcp,udp}"')
        
# SOURCE_INTERFACE_ZONE tests
# SOURCE_INTERFACE_ZONE tests
# SOURCE_INTERFACE_ZONE tests

    def test_011_condition_source_interface(self):
        """Check SOURCE_INTERFACE_ZONE is 1"""
        condition = {"type": "SOURCE_INTERFACE_ZONE","op":"IS","value": "1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x000000ff 1')

    def test_011_condition_source_interface_invert(self):
        """Check SOURCE_INTERFACE_ZONE is not 1"""
        condition = {"type": "SOURCE_INTERFACE_ZONE","op":"IS_NOT","value": "1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x000000ff != 1')

    def test_011_condition_source_interface_multiple(self):
        """Check SOURCE_INTERFACE_ZONE is 1,2"""
        condition = {"type": "SOURCE_INTERFACE_ZONE","op":"IS","value": "1,2"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x000000ff "{1,2}"')

    def test_011_condition_source_interface_multiple_invert(self):
        """Check SOURCE_INTERFACE_ZONE is not 1,2"""
        condition = {"type": "SOURCE_INTERFACE_ZONE","op":"IS_NOT","value": "1,2"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x000000ff != "{1,2}"')
        
    def test_011_condition_source_interface_wan(self):
        """Check SOURCE_INTERFACE_ZONE is wan"""
        condition = {"type": "SOURCE_INTERFACE_ZONE","op":"IS","value": "wan"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x01000000 != 0')

    def test_011_condition_source_interface_non_wan(self):
        """Check SOURCE_INTERFACE_ZONE is non_wan"""
        condition = {"type": "SOURCE_INTERFACE_ZONE","op":"IS","value": "non_wan"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x01000000 == 0')

    def test_011_condition_source_interface_mix(self):
        """Check that mixing interface indexes and "wan" or "non_wan" is not allowed"""
        condition = {"type": "SOURCE_INTERFACE_ZONE","op":"IS","value": "1,wan"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

# DESTINATION_INTERFACE_ZONE tests
# DESTINATION_INTERFACE_ZONE tests
# DESTINATION_INTERFACE_ZONE tests

    def test_012_condition_destination_interface(self):
        """Check DESTINATION_INTERFACE_ZONE is 1"""
        condition = {"type": "DESTINATION_INTERFACE_ZONE","op":"IS","value": "1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x0000ff00 1')

    def test_012_condition_destination_interface_invert(self):
        """Check DESTINATION_INTERFACE_ZONE is not 1"""
        condition = {"type": "DESTINATION_INTERFACE_ZONE","op":"IS_NOT","value": "1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x0000ff00 != 1')

    def test_012_condition_destination_interface_multiple(self):
        """Check DESTINATION_INTERFACE_ZONE is 1,2"""
        condition = {"type": "DESTINATION_INTERFACE_ZONE","op":"IS","value": "1,2"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x0000ff00 "{1,2}"')

    def test_012_condition_destination_interface_multiple_invert(self):
        """Check DESTINATION_INTERFACE_ZONE is not 1,2"""
        condition = {"type": "DESTINATION_INTERFACE_ZONE","op":"IS_NOT","value": "1,2"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x0000ff00 != "{1,2}"')
        
    def test_012_condition_destination_interface_wan(self):
        """Check DESTINATION_INTERFACE_ZONE is wan"""
        condition = {"type": "DESTINATION_INTERFACE_ZONE","op":"IS","value": "wan"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x02000000 != 0')

    def test_012_condition_destination_interface_non_wan(self):
        """Check DESTINATION_INTERFACE_ZONE is non_wan"""
        condition = {"type": "DESTINATION_INTERFACE_ZONE","op":"IS","value": "non_wan"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'mark and 0x02000000 == 0')

    def test_012_condition_destination_interface_mix(self):
        """Check that mixing interface indexes and "wan" or "non_wan" is not allowed"""
        condition = {"type": "DESTINATION_INTERFACE_ZONE","op":"IS","value": "1,wan"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

# CLIENT_INTERFACE_ZONE tests
# CLIENT_INTERFACE_ZONE tests
# CLIENT_INTERFACE_ZONE tests

    def test_013_condition_client_interface(self):
        """Check CLIENT_INTERFACE_ZONE is 1"""
        condition = {"type": "CLIENT_INTERFACE_ZONE","op":"IS","value": "1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x000000ff 1')

    def test_013_condition_client_interface_invert(self):
        """Check CLIENT_INTERFACE_ZONE is not 1"""
        condition = {"type": "CLIENT_INTERFACE_ZONE","op":"IS_NOT","value": "1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x000000ff != 1')

    def test_013_condition_client_interface_multiple(self):
        """Check CLIENT_INTERFACE_ZONE is 1,2"""
        condition = {"type": "CLIENT_INTERFACE_ZONE","op":"IS","value": "1,2"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x000000ff "{1,2}"')

    def test_013_condition_client_interface_multiple_invert(self):
        """Check CLIENT_INTERFACE_ZONE is not 1,2"""
        condition = {"type": "CLIENT_INTERFACE_ZONE","op":"IS_NOT","value": "1,2"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x000000ff != "{1,2}"')
        
    def test_013_condition_client_interface_wan(self):
        """Check CLIENT_INTERFACE_ZONE is wan"""
        condition = {"type": "CLIENT_INTERFACE_ZONE","op":"IS","value": "wan"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x01000000 != 0')

    def test_013_condition_client_interface_non_wan(self):
        """Check CLIENT_INTERFACE_ZONE is non_wan"""
        condition = {"type": "CLIENT_INTERFACE_ZONE","op":"IS","value": "non_wan"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x01000000 == 0')

    def test_013_condition_client_interface_mix(self):
        """Check that mixing interface indexes and "wan" or "non_wan" is not allowed"""
        condition = {"type": "CLIENT_INTERFACE_ZONE","op":"IS","value": "1,wan"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

# SERVER_INTERFACE_ZONE tests
# SERVER_INTERFACE_ZONE tests
# SERVER_INTERFACE_ZONE tests

    def test_014_condition_server_interface(self):
        """Check SERVER_INTERFACE_ZONE is 1"""
        condition = {"type": "SERVER_INTERFACE_ZONE","op":"IS","value": "1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x0000ff00 1')

    def test_014_condition_server_interface_invert(self):
        """Check SERVER_INTERFACE_ZONE is not 1"""
        condition = {"type": "SERVER_INTERFACE_ZONE","op":"IS_NOT","value": "1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x0000ff00 != 1')

    def test_014_condition_server_interface_multiple(self):
        """Check SERVER_INTERFACE_ZONE is 1,2"""
        condition = {"type": "SERVER_INTERFACE_ZONE","op":"IS","value": "1,2"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x0000ff00 "{1,2}"')

    def test_014_condition_server_interface_multiple_invert(self):
        """Check SERVER_INTERFACE_ZONE is not 1,2"""
        condition = {"type": "SERVER_INTERFACE_ZONE","op":"IS_NOT","value": "1,2"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x0000ff00 != "{1,2}"')
        
    def test_014_condition_server_interface_wan(self):
        """Check SERVER_INTERFACE_ZONE is wan"""
        condition = {"type": "SERVER_INTERFACE_ZONE","op":"IS","value": "wan"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x02000000 != 0')

    def test_014_condition_server_interface_non_wan(self):
        """Check SERVER_INTERFACE_ZONE is non_wan"""
        condition = {"type": "SERVER_INTERFACE_ZONE","op":"IS","value": "non_wan"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ct mark and 0x02000000 == 0')

    def test_014_condition_server_interface_mix(self):
        """Check that mixing interface indexes and "wan" or "non_wan" is not allowed"""
        condition = {"type": "SERVER_INTERFACE_ZONE","op":"IS","value": "1,wan"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

# SOURCE_INTERFACE_NAME tests
# SOURCE_INTERFACE_NAME tests
# SOURCE_INTERFACE_NAME tests

    def test_011_condition_source_interface(self):
        """Check SOURCE_INTERFACE_NAME is lo"""
        condition = {"type": "SOURCE_INTERFACE_NAME","op":"IS","value": "lo"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'iifname lo')

    def test_011_condition_source_interface_invert(self):
        """Check SOURCE_INTERFACE_NAME is not lo"""
        condition = {"type": "SOURCE_INTERFACE_NAME","op":"IS_NOT","value": "lo"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'iifname != lo')

# DESTINATION_INTERFACE_NAME tests
# DESTINATION_INTERFACE_NAME tests
# DESTINATION_INTERFACE_NAME tests

    def test_012_condition_destination_interface(self):
        """Check DESTINATION_INTERFACE_NAME is lo"""
        condition = {"type": "DESTINATION_INTERFACE_NAME","op":"IS","value": "lo"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'oifname lo')

    def test_012_condition_destination_interface_invert(self):
        """Check DESTINATION_INTERFACE_NAME is not lo"""
        condition = {"type": "DESTINATION_INTERFACE_NAME","op":"IS_NOT","value": "lo"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'oifname != lo')

# SOURCE_ADDRESS tests
# SOURCE_ADDRESS tests
# SOURCE_ADDRESS tests

    def test_020_condition_source_address_ipv4(self):
        """Check SOURCE_ADDRESS is 1.2.3.4"""
        condition = {"type": "SOURCE_ADDRESS","op":"IS","value": "1.2.3.4"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip saddr 1.2.3.4')

    def test_020_condition_source_address_ipv4_invert(self):
        """Check SOURCE_ADDRESS is 1.2.3.4"""
        condition = {"type": "SOURCE_ADDRESS","op":"IS_NOT","value": "1.2.3.4"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip saddr != 1.2.3.4')

    def test_020_condition_source_address_ipv4_subnet(self):
        """Check SOURCE_ADDRESS is 1.2.3.4"""
        condition = {"type": "SOURCE_ADDRESS","op":"IS","value": "1.2.3.4/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip saddr 1.2.3.4/24')

    def test_020_condition_source_address_ipv4_subnet_invert(self):
        """Check SOURCE_ADDRESS is 1.2.3.4"""
        condition = {"type": "SOURCE_ADDRESS","op":"IS_NOT","value": "1.2.3.4/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip saddr != 1.2.3.4/24')
        
    def test_020_condition_source_address_ipv4_multiple(self):
        """Check SOURCE_ADDRESS is 1.2.3.4"""
        condition = {"type": "SOURCE_ADDRESS","op":"IS","value": "1.2.3.4,1.2.3.5/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip saddr "{1.2.3.4,1.2.3.5/24}"')

    def test_020_condition_source_address_ipv4_multiple_invert(self):
        """Check SOURCE_ADDRESS is 1.2.3.4"""
        condition = {"type": "SOURCE_ADDRESS","op":"IS_NOT","value": "1.2.3.4,1.2.3.5/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip saddr != "{1.2.3.4,1.2.3.5/24}"')
        
    def test_020_condition_source_address_ipv6(self):
        """Check SOURCE_ADDRESS is fe80::1"""
        condition = {"type": "SOURCE_ADDRESS","op":"IS","value": "fe80::1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip6 saddr fe80::1')

    def test_020_condition_source_address_ipv6_invert(self):
        """Check SOURCE_ADDRESS is fe80::1"""
        condition = {"type": "SOURCE_ADDRESS","op":"IS_NOT","value": "fe80::1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip6 saddr != fe80::1')

# DESTINATION_ADDRESS tests
# DESTINATION_ADDRESS tests
# DESTINATION_ADDRESS tests

    def test_021_condition_destination_address_ipv4(self):
        """Check DESTINATION_ADDRESS is 1.2.3.4"""
        condition = {"type": "DESTINATION_ADDRESS","op":"IS","value": "1.2.3.4"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip daddr 1.2.3.4')

    def test_021_condition_destination_address_ipv4_invert(self):
        """Check DESTINATION_ADDRESS is 1.2.3.4"""
        condition = {"type": "DESTINATION_ADDRESS","op":"IS_NOT","value": "1.2.3.4"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip daddr != 1.2.3.4')

    def test_021_condition_destination_address_ipv4_subnet(self):
        """Check DESTINATION_ADDRESS is 1.2.3.4"""
        condition = {"type": "DESTINATION_ADDRESS","op":"IS","value": "1.2.3.4/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip daddr 1.2.3.4/24')

    def test_021_condition_destination_address_ipv4_subnet_invert(self):
        """Check DESTINATION_ADDRESS is 1.2.3.4"""
        condition = {"type": "DESTINATION_ADDRESS","op":"IS_NOT","value": "1.2.3.4/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip daddr != 1.2.3.4/24')
        
    def test_021_condition_destination_address_ipv4_multiple(self):
        """Check DESTINATION_ADDRESS is 1.2.3.4"""
        condition = {"type": "DESTINATION_ADDRESS","op":"IS","value": "1.2.3.4,1.2.3.5/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip daddr "{1.2.3.4,1.2.3.5/24}"')

    def test_021_condition_destination_address_ipv4_multiple_invert(self):
        """Check DESTINATION_ADDRESS is 1.2.3.4"""
        condition = {"type": "DESTINATION_ADDRESS","op":"IS_NOT","value": "1.2.3.4,1.2.3.5/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip daddr != "{1.2.3.4,1.2.3.5/24}"')
        
    def test_021_condition_destination_address_ipv6(self):
        """Check DESTINATION_ADDRESS is fe80::1"""
        condition = {"type": "DESTINATION_ADDRESS","op":"IS","value": "fe80::1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip6 daddr fe80::1')

    def test_021_condition_destination_address_ipv6_invert(self):
        """Check DESTINATION_ADDRESS is fe80::1"""
        condition = {"type": "DESTINATION_ADDRESS","op":"IS_NOT","value": "fe80::1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'ip6 daddr != fe80::1')

# CLIENT_ADDRESS tests
# CLIENT_ADDRESS tests
# CLIENT_ADDRESS tests

    def test_022_condition_client_address_ipv4(self):
        """Check CLIENT_ADDRESS is 1.2.3.4"""
        condition = {"type": "CLIENT_ADDRESS","op":"IS","value": "1.2.3.4"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_address ipv4_addr 1.2.3.4')

    def test_022_condition_client_address_ipv4_invert(self):
        """Check CLIENT_ADDRESS is 1.2.3.4"""
        condition = {"type": "CLIENT_ADDRESS","op":"IS_NOT","value": "1.2.3.4"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_address ipv4_addr != 1.2.3.4')

    def test_022_condition_client_address_ipv4_subnet(self):
        """Check CLIENT_ADDRESS is 1.2.3.4"""
        condition = {"type": "CLIENT_ADDRESS","op":"IS","value": "1.2.3.4/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_address ipv4_addr 1.2.3.4/24')

    def test_022_condition_client_address_ipv4_subnet_invert(self):
        """Check CLIENT_ADDRESS is 1.2.3.4"""
        condition = {"type": "CLIENT_ADDRESS","op":"IS_NOT","value": "1.2.3.4/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_address ipv4_addr != 1.2.3.4/24')
        
    def test_022_condition_client_address_ipv4_multiple(self):
        """Check CLIENT_ADDRESS is 1.2.3.4"""
        condition = {"type": "CLIENT_ADDRESS","op":"IS","value": "1.2.3.4,1.2.3.5/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_address ipv4_addr "{1.2.3.4,1.2.3.5/24}"')

    def test_022_condition_client_address_ipv4_multiple_invert(self):
        """Check CLIENT_ADDRESS is 1.2.3.4"""
        condition = {"type": "CLIENT_ADDRESS","op":"IS_NOT","value": "1.2.3.4,1.2.3.5/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_address ipv4_addr != "{1.2.3.4,1.2.3.5/24}"')
        
    def test_022_condition_client_address_ipv6(self):
        """Check CLIENT_ADDRESS is fe80::1"""
        condition = {"type": "CLIENT_ADDRESS","op":"IS","value": "fe80::1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_address ipv6_addr fe80::1')

    def test_022_condition_client_address_ipv6_invert(self):
        """Check CLIENT_ADDRESS is fe80::1"""
        condition = {"type": "CLIENT_ADDRESS","op":"IS_NOT","value": "fe80::1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_address ipv6_addr != fe80::1')

# SERVER_ADDRESS tests
# SERVER_ADDRESS tests
# SERVER_ADDRESS tests

    def test_023_condition_server_address_ipv4(self):
        """Check SERVER_ADDRESS is 1.2.3.4"""
        condition = {"type": "SERVER_ADDRESS","op":"IS","value": "1.2.3.4"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_address ipv4_addr 1.2.3.4')

    def test_023_condition_server_address_ipv4_invert(self):
        """Check SERVER_ADDRESS is 1.2.3.4"""
        condition = {"type": "SERVER_ADDRESS","op":"IS_NOT","value": "1.2.3.4"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_address ipv4_addr != 1.2.3.4')

    def test_023_condition_server_address_ipv4_subnet(self):
        """Check SERVER_ADDRESS is 1.2.3.4"""
        condition = {"type": "SERVER_ADDRESS","op":"IS","value": "1.2.3.4/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_address ipv4_addr 1.2.3.4/24')

    def test_023_condition_server_address_ipv4_subnet_invert(self):
        """Check SERVER_ADDRESS is 1.2.3.4"""
        condition = {"type": "SERVER_ADDRESS","op":"IS_NOT","value": "1.2.3.4/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_address ipv4_addr != 1.2.3.4/24')
        
    def test_023_condition_server_address_ipv4_multiple(self):
        """Check SERVER_ADDRESS is 1.2.3.4"""
        condition = {"type": "SERVER_ADDRESS","op":"IS","value": "1.2.3.4,1.2.3.5/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_address ipv4_addr "{1.2.3.4,1.2.3.5/24}"')

    def test_023_condition_server_address_ipv4_multiple_invert(self):
        """Check SERVER_ADDRESS is 1.2.3.4"""
        condition = {"type": "SERVER_ADDRESS","op":"IS_NOT","value": "1.2.3.4,1.2.3.5/24"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_address ipv4_addr != "{1.2.3.4,1.2.3.5/24}"')
        
    def test_023_condition_server_address_ipv6(self):
        """Check SERVER_ADDRESS is fe80::1"""
        condition = {"type": "SERVER_ADDRESS","op":"IS","value": "fe80::1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_address ipv6_addr fe80::1')

    def test_023_condition_server_address_ipv6_invert(self):
        """Check SERVER_ADDRESS is fe80::1"""
        condition = {"type": "SERVER_ADDRESS","op":"IS_NOT","value": "fe80::1"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_address ipv6_addr != fe80::1')
        
# SOURCE_PORT tests
# SOURCE_PORT tests
# SOURCE_PORT tests

    def test_030_condition_source_port_protocol_required(self):
        """Check SOURCE_PORT also requireds an IP_PROTOCOL condition"""
        condition = {"type": "SOURCE_PORT","op":"IS","value": "1234"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

    def test_030_condition_source_port_protocol_required_is(self):
        """Check SOURCE_PORT also requireds an IP_PROTOCOL condition with IS"""
        condition = {"type": "SOURCE_PORT","op":"IS","value": "1234"}
        proto = {"type": "IP_PROTOCOL","op":"IS_NOT","value": "tcp"}
        try:
            str = nftables_util.conditions_expression([condition,proto])
            assert(False)
        except:
            assert(True)

    def test_030_condition_source_port_protocol_required_is_single(self):
        """Check SOURCE_PORT also requireds an IP_PROTOCOL condition with IS and only one protocol"""
        condition = {"type": "SOURCE_PORT","op":"IS","value": "1234"}
        proto = {"type": "IP_PROTOCOL","op":"IS_NOT","value": "tcp,udp"}
        try:
            str = nftables_util.conditions_expression([condition,proto])
            assert(False)
        except:
            assert(True)
            
    def test_030_condition_source_port(self):
        """Check SOURCE_PORT is 1234"""
        condition = {"type": "SOURCE_PORT","op":"IS","value": "1234"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp sport 1234 ip protocol tcp')

    def test_030_condition_source_port_invert(self):
        """Check SOURCE_PORT is 1234"""
        condition = {"type": "SOURCE_PORT","op":"IS_NOT","value": "1234"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp sport != 1234 ip protocol tcp')

    def test_030_condition_source_port_range(self):
        """Check SOURCE_PORT is 1234"""
        condition = {"type": "SOURCE_PORT","op":"IS","value": "1235-1236"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp sport 1235-1236 ip protocol tcp')

    def test_030_condition_source_port_range_invert(self):
        """Check SOURCE_PORT is 1234"""
        condition = {"type": "SOURCE_PORT","op":"IS_NOT","value": "1235-1236"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp sport != 1235-1236 ip protocol tcp')
        
    def test_030_condition_source_port_multiple(self):
        """Check SOURCE_PORT is 1234,1235-1236"""
        condition = {"type": "SOURCE_PORT","op":"IS","value": "1234,1235-1236"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp sport "{1234,1235-1236}" ip protocol tcp')

    def test_030_condition_source_port_multiple_invert(self):
        """Check SOURCE_PORT is not 1234,1235-1236"""
        condition = {"type": "SOURCE_PORT","op":"IS_NOT","value": "1234,1235-1236"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp sport != "{1234,1235-1236}" ip protocol tcp')

# DESTINATION_PORT tests
# DESTINATION_PORT tests
# DESTINATION_PORT tests

    def test_031_condition_destination_port_protocol_required(self):
        """Check DESTINATION_PORT also requireds an IP_PROTOCOL condition"""
        condition = {"type": "DESTINATION_PORT","op":"IS","value": "1234"}
        try:
            str = nftables_util.conditions_expression([condition])
            assert(False)
        except:
            assert(True)

    def test_031_condition_destination_port_protocol_required_is(self):
        """Check DESTINATION_PORT also requireds an IP_PROTOCOL condition with IS"""
        condition = {"type": "DESTINATION_PORT","op":"IS","value": "1234"}
        proto = {"type": "IP_PROTOCOL","op":"IS_NOT","value": "tcp"}
        try:
            str = nftables_util.conditions_expression([condition,proto])
            assert(False)
        except:
            assert(True)

    def test_031_condition_destination_port_protocol_required_is_single(self):
        """Check DESTINATION_PORT also requireds an IP_PROTOCOL condition with IS and only one protocol"""
        condition = {"type": "DESTINATION_PORT","op":"IS","value": "1234"}
        proto = {"type": "IP_PROTOCOL","op":"IS_NOT","value": "tcp,udp"}
        try:
            str = nftables_util.conditions_expression([condition,proto])
            assert(False)
        except:
            assert(True)
            
    def test_031_condition_destination_port(self):
        """Check DESTINATION_PORT is 1234"""
        condition = {"type": "DESTINATION_PORT","op":"IS","value": "1234"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp dport 1234 ip protocol tcp')

    def test_031_condition_destination_port_invert(self):
        """Check DESTINATION_PORT is 1234"""
        condition = {"type": "DESTINATION_PORT","op":"IS_NOT","value": "1234"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp dport != 1234 ip protocol tcp')

    def test_031_condition_destination_port_range(self):
        """Check DESTINATION_PORT is 1234"""
        condition = {"type": "DESTINATION_PORT","op":"IS","value": "1235-1236"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp dport 1235-1236 ip protocol tcp')

    def test_031_condition_destination_port_range_invert(self):
        """Check DESTINATION_PORT is 1234"""
        condition = {"type": "DESTINATION_PORT","op":"IS_NOT","value": "1235-1236"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp dport != 1235-1236 ip protocol tcp')
        
    def test_031_condition_destination_port_multiple(self):
        """Check DESTINATION_PORT is 1234,1235-1236"""
        condition = {"type": "DESTINATION_PORT","op":"IS","value": "1234,1235-1236"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp dport "{1234,1235-1236}" ip protocol tcp')

    def test_031_condition_destination_port_multiple_invert(self):
        """Check DESTINATION_PORT is not 1234,1235-1236"""
        condition = {"type": "DESTINATION_PORT","op":"IS_NOT","value": "1234,1235-1236"}
        proto = {"type": "IP_PROTOCOL","op":"IS","value": "tcp"}
        str = nftables_util.conditions_expression([condition,proto])
        print(str)
        assert(str == 'tcp dport != "{1234,1235-1236}" ip protocol tcp')

# CLIENT_PORT tests
# CLIENT_PORT tests
# CLIENT_PORT tests

    def test_032_condition_client_port(self):
        """Check CLIENT_PORT is 1234"""
        condition = {"type": "CLIENT_PORT","op":"IS","value": "1234"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_port integer 1234')

    def test_032_condition_client_port_invert(self):
        """Check CLIENT_PORT is 1234"""
        condition = {"type": "CLIENT_PORT","op":"IS_NOT","value": "1234"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_port integer != 1234')

    def test_032_condition_client_port_range(self):
        """Check CLIENT_PORT is 1234"""
        condition = {"type": "CLIENT_PORT","op":"IS","value": "1235-1236"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_port integer 1235-1236')

    def test_032_condition_client_port_range_invert(self):
        """Check CLIENT_PORT is 1234"""
        condition = {"type": "CLIENT_PORT","op":"IS_NOT","value": "1235-1236"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_port integer != 1235-1236')
        
    def test_032_condition_client_port_multiple(self):
        """Check CLIENT_PORT is 1234,1235-1236"""
        condition = {"type": "CLIENT_PORT","op":"IS","value": "1234,1235-1236"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_port integer "{1234,1235-1236}"')

    def test_032_condition_client_port_multiple_invert(self):
        """Check CLIENT_PORT is not 1234,1235-1236"""
        condition = {"type": "CLIENT_PORT","op":"IS_NOT","value": "1234,1235-1236"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id client_port integer != "{1234,1235-1236}"')

# SERVER_PORT tests
# SERVER_PORT tests
# SERVER_PORT tests

    def test_032_condition_server_port(self):
        """Check SERVER_PORT is 1234"""
        condition = {"type": "SERVER_PORT","op":"IS","value": "1234"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_port integer 1234')

    def test_032_condition_server_port_invert(self):
        """Check SERVER_PORT is 1234"""
        condition = {"type": "SERVER_PORT","op":"IS_NOT","value": "1234"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_port integer != 1234')

    def test_032_condition_server_port_range(self):
        """Check SERVER_PORT is 1234"""
        condition = {"type": "SERVER_PORT","op":"IS","value": "1235-1236"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_port integer 1235-1236')

    def test_032_condition_server_port_range_invert(self):
        """Check SERVER_PORT is 1234"""
        condition = {"type": "SERVER_PORT","op":"IS_NOT","value": "1235-1236"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_port integer != 1235-1236')
        
    def test_032_condition_server_port_multiple(self):
        """Check SERVER_PORT is 1234,1235-1236"""
        condition = {"type": "SERVER_PORT","op":"IS","value": "1234,1235-1236"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_port integer "{1234,1235-1236}"')

    def test_032_condition_server_port_multiple_invert(self):
        """Check SERVER_PORT is not 1234,1235-1236"""
        condition = {"type": "SERVER_PORT","op":"IS_NOT","value": "1234,1235-1236"}
        str = nftables_util.conditions_expression([condition])
        print(str)
        assert(str == 'dict session ct id server_port integer != "{1234,1235-1236}"')

# ACTIONS
# ACTIONS
# ACTIONS

    def test_100_action_reject(self):
        """Check action REJECT"""
        action = {"type": "REJECT"}
        str = nftables_util.action_expression(action)
        print(str)
        assert(str == 'reject')

    def test_101_action_accept(self):
        """Check action ACCEPT"""
        action = {"type": "ACCEPT"}
        str = nftables_util.action_expression(action)
        print(str)
        assert(str == 'accept')

    def test_102_action_jump(self):
        """Check action JUMP"""
        action = {"type": "JUMP", "chain":"target"}
        str = nftables_util.action_expression(action)
        print(str)
        assert(str == 'jump target')

    def test_103_action_goto(self):
        """Check action GOTO"""
        action = {"type": "GOTO", "chain":"target"}
        str = nftables_util.action_expression(action)
        print(str)
        assert(str == 'goto target')

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
                "value": "tcp"
            }],
            "op": "IS",
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
                "value": "tcp"
            }],
            "op": "IS",
            "action": {
                "type": "ACCEPT"
            }
        }
        exp_str = nftables_util.rule_expression(rule)
        print(exp_str)
        rule_str = nftables_util.rule_cmd(rule, "inet", "forward", "forward-filter")
        print(rule_str)
        assert(exp_str == 'ip protocol tcp accept')
        assert(rule_str == 'nft add rule inet forward forward-filter ip protocol tcp accept')
        


    @staticmethod
    def finalTearDown(self):
        pass
    
test_registry.register_module("nftables_util", NftablesTests)
