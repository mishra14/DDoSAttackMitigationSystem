#!/bin/bash

BBh1 hping3 --flood --udp AAh1 &
BBh1 hping3 --flood --udp AAh2 &
BAh1 hping3 --flood --udp AAh1 &
BAh1 hping3 --flood --udp AAh2 &
BBh2 hping3 --flood --udp AAh1 &
BBh2 hping3 --flood --udp AAh2 &
BAh2 hping3 --flood --udp AAh1 &
BAh2 hping3 --flood --udp AAh2 & 
ABh1 hping3 --flood --udp AAh1 &
ABh1 hping3 --flood --udp AAh2 &
ABh2 hping3 --flood --udp AAh1 &
ABh2 hping3 --flood --udp AAh2 &
