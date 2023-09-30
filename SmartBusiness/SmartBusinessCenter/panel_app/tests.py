from django.test import TestCase
from panel_app.utils.utils import is_valid_ipv4_address, scan_network, find_hostname_on_ips

class ScanNetWorkScanTest(TestCase):
    def test_scan_network(self):
        result = is_valid_ipv4_address('190.20.30.50')
        self.assertEqual(result,True)
    
    def test_scan_invalid_network(self):
        result = is_valid_ipv4_address('234.1212.23')
        self.assertEqual(result,False)

    def test_no_inrage_range_ip(self):
        result = is_valid_ipv4_address('256.190.0.30')
        self.assertEqual(result,False)

    def test_outputdata(self):
        result = scan_network('192.168.0')
        print(result)

    def test_hostname_ip(self):
        result = find_hostname_on_ips()
        self.assertEqual(result,True)
