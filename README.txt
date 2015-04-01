Group E Members - 
Ankit Mishra - mankit
Gouthaman Kumarappan - goku
Simon Wimmer - wimmers


instructions- 
1. Run custom controller 1 (for domain A)
sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6633 ryu/ryu/app/Controller1.py

2. Run custom controller 2 (for domain B)
sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6634 ryu/ryu/app/Controller2.py

3. Run the custom topology
sudo python customTopology.py

(Protected nodes are AAh1 and AAh2 only)
4. To start inter domain attack
BBh1 hping3 --flood --udp AAh1 &
BBh1 hping3 --flood --udp AAh2 &
BAh1 hping3 --flood --udp AAh1 &
BAh1 hping3 --flood --udp AAh2 &
.. etc.

5. To start intra domain attack 

ABh1 hping3 --flood --udp AAh1 &
ABh1 hping3 --flood --udp AAh2 &
ABh2 hping3 --flood --udp AAh1 &
ABh2 hping3 --flood --udp AAh2 &
.. etc.

6. Monitor the controller A and B consoles to see the results and the effective bandwidth on the links.
