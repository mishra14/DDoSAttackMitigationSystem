#!/bin/bash

BBh1 hping3 --flood --udp AAh1 &
BBh1 hping3 --flood --udp AAh2 &
BAh1 hping3 --flood --udp AAh1 &
BAh1 hping3 --flood --udp AAh2 &
BBh1 hping3 --flood --udp AAh1 &
BBh1 hping3 --flood --udp AAh2 &
BAh1 hping3 --flood --udp AAh1 &
BAh1 hping3 --flood --udp AAh2 & 

