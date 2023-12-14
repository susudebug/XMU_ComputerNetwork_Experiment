# -*- coding: utf-8 -*-
import codecs
import json
import os
import sys
import subprocess

ips = {
    '10.0.1.100': 1,
    '10.0.1.1': 1,
    '10.0.2.1': 1,
    '10.0.3.1': 1,
    '10.0.2.2': 1,
    '10.0.3.2': 1,
    '192.168.3.1': 1,
    '192.168.3.2': 1,
    '192.168.2.2': 1,
    '192.168.2.200': 1,
    '172.24.3.2': 1,
    '172.24.3.30': 1,
}


def test_ping(ip, expect_result):
    process = subprocess.Popen("ping -c 1 %s" % ip, shell=True, stdout=subprocess.PIPE)
    a, b = process.communicate()
    result = 2
    if '0% packet loss' in a:
        result = 1
    if 'Destination Net Unreachable' in a:
        result = 0
    if result == expect_result:
        return True
    else:
        return False


def test_traceroute(ip, expect_hop):
    process = subprocess.Popen("traceroute %s" % ip, shell=True, stdout=subprocess.PIPE)
    a, b = process.communicate()
    listx = a.split("\n")
    x = 0
    for x in range(len(listx)):
        if listx[x].find("traceroute to") != -1:
            break
    count = 0
    ip_address = ''
    for i in range(x+1, len(listx)):
        if str.strip(listx[i]) == '':
            break
        count += 1
        if listx[i].find('* * *') != -1 or listx[i].find('***') != -1:
            return False
        ip_address = listx[i][listx[i].find('(')+1:listx[i].find(')')]
        if ip_address not in ips:
            return False
    if ip_address != ip:
        return False
    if count == expect_hop:
        return True
    else:
        return False


if __name__ == '__main__':
    if sys.argv[1] == 'Testcase1' or sys.argv[1] == 'Testcase10' or sys.argv[1] == 'Testcase15':
        result = True
        for ip in ips:
            if not test_ping(ip, ips[ip]):
		print("this fail")
                result = False
                break
        if result and not test_traceroute('192.168.2.200', 3):
            result = False
	    print("traceroute fail")
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase2' or sys.argv[1] == 'Testcase11':
        result = True
        for ip in ips:
            if not test_ping(ip, 1):
                result = False
                break
        if result and not test_traceroute('172.24.3.30', 3):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase3' or sys.argv[1] == 'Testcase12':
        result = True
        for ip in ips:
            if result and not test_ping(ip, 1):
                result = False
                break
        if not test_traceroute('10.0.1.100', 3):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase4':
        result = True
        ips['10.0.2.1'] = 0
        ips['10.0.2.2'] = 0
        for ip in ips:
            if not test_ping(ip, ips[ip]):
                result = False
                break
        if result and not test_traceroute('192.168.2.200', 4):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase5':
        result = True
        ips['10.0.2.1'] = 0
        ips['10.0.2.2'] = 0
        for ip in ips:
            if not test_ping(ip, ips[ip]):
                result = False
                break
        if result and not test_traceroute('172.24.3.30', 3):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase6':
        result = True
        ips['10.0.2.1'] = 0
        ips['10.0.2.2'] = 0
        for ip in ips:
            if not test_ping(ip, ips[ip]):
                result = False
                break
        if result and not test_traceroute('10.0.1.100', 3):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase7':
        result = True
        ips['10.0.2.1'] = 0
        ips['10.0.2.2'] = 0
        ips['192.168.3.1'] = 0
        ips['192.168.3.2'] = 0
        ips['192.168.2.2'] = 0
        ips['192.168.2.200'] = 0
        for ip in ips:
            if not test_ping(ip, ips[ip]):
                result = False
                break
        if result and not test_traceroute('172.24.3.30', 3):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase8':
        result = True
        for ip in ips:
            ips[ip] = 0
        ips['192.168.2.2'] = 1
        ips['192.168.2.200'] = 1
        for ip in ips:
            if not test_ping(ip, ips[ip]):
                result = False
                break
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase9':
        result = True
        ips['10.0.2.1'] = 0
        ips['10.0.2.2'] = 0
        ips['192.168.3.1'] = 0
        ips['192.168.3.2'] = 0
        ips['192.168.2.2'] = 0
        ips['192.168.2.200'] = 0
        for ip in ips:
            if not test_ping(ip, ips[ip]):
                result = False
                break
        if result and not test_traceroute('10.0.1.100', 3):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase13':
        result = True
        ips['10.0.1.1'] = 0
        ips['10.0.1.100'] = 0
        for ip in ips:
            if not test_ping(ip, ips[ip]):
                result = False
                break
        if result and not test_traceroute('172.24.3.30', 3):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'
    elif sys.argv[1] == 'Testcase14':
        result = True
        ips['10.0.1.1'] = 0
        ips['10.0.1.100'] = 0
        for ip in ips:
            if not test_ping(ip, ips[ip]):
                result = False
                break
        if result and not test_traceroute('10.0.3.1', 2):
            result = False
        print '%s: ' % sys.argv[1],
        if result:
            print 'Pass'
        else:
            print 'Failed'


