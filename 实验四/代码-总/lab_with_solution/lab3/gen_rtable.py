#!/usr/bin/env python

IPCONFIG_FILE = '/home/ubuntu/pwospf/IP_CONFIG'
IP_SETTING={}
f = open(IPCONFIG_FILE, 'r')
for line in f:
    if(len(line.split()) == 0):
        break
    name, ip = line.split()
    print name, ip
    IP_SETTING[name] = ip
f.close()

for h in [1,2,3]:
    rtable = open("rtable.router%s" % h, 'w')
    if h == 1:
        rtable.write('%s\t%s\t%s\t%s\n' % (IP_SETTING['client'], IP_SETTING['client'], '255.255.255.255', 'eth1') )
        rtable.write('%s\t%s\t%s\t%s\n' % ('10.0.2.0', IP_SETTING['router2-eth1'], '255.255.255.0', 'eth2') )
        rtable.write('%s\t%s\t%s\t%s\n' % ('10.0.3.0', IP_SETTING['router3-eth1'], '255.255.255.0', 'eth3') )
    elif h == 2:
        rtable.write('%s\t%s\t%s\t%s\n' % ('10.0.2.0', IP_SETTING['router1-eth2'], '255.255.255.0', 'eth1') )
        rtable.write('%s\t%s\t%s\t%s\n' % (IP_SETTING['server1'], IP_SETTING['server1'], '255.255.255.255', 'eth2') )
        rtable.write('%s\t%s\t%s\t%s\n' % ('192.168.3.0', IP_SETTING['router3-eth3'], '255.255.255.0', 'eth3') )
    elif h == 3:
        rtable.write('%s\t%s\t%s\t%s\n' % ('10.0.3.0', IP_SETTING['router1-eth3'], '255.255.255.0', 'eth1') )
        rtable.write('%s\t%s\t%s\t%s\n' % (IP_SETTING['server2'], IP_SETTING['server2'], '255.255.255.255', 'eth2') )
        rtable.write('%s\t%s\t%s\t%s\n' % ('192.168.3.0', IP_SETTING['router2-eth3'], '255.255.255.0', 'eth3') )
    rtable.close()

