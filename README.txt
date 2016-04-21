This repo is for a python based sdn controllers that can detect a DDoS attack on target hosts.
Further, the controllers can mitigate the attack by limiting the bandwidth between the target and the attacker node.

Team Members - 
Ankit Mishra
Gouthaman Kumarappan
Simon Wimmer


Instructions- 
1. Run custom controller 1 (for domain A)
sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6633 ryu/ryu/app/Controller1.py | tee log1.txt

2. Run custom controller 2 (for domain B)
sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6634 ryu/ryu/app/Controller2.py | tee log2.txt

Note - The above 2 commands display the controller outputs on the console and also log them to log1.txt and log2.txt
	   In order to not log the outputs, please use the following commands - 

sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6633 ryu/ryu/app/Controller1.py

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
