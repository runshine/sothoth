#!/bin/sh

brctl addif br-openvpn $dev
ip link set $dev up
echo "${date}: device $dev is up"