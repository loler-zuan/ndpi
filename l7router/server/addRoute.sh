#! /bin/sh
ip route add table 1 via 10.0.2.2 dev eth3
ip route add table 2 via 10.0.2.2 dev eth4
ip rule add fwmark 1 table 1
ip rule add fwmark 2 table 1
