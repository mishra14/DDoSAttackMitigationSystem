Group E Members - 
Ankit Mishra - mankit
Gouthaman Kumarappan - goku
Simon Wimmer - wimmers


instructions- 
1. Run custom controller A
sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6633 ryu/ryu/app/simple_switch_13.py

2. Run custom controller B
sudo python ./ryu/bin/ryu-manager --ofp-tcp-listen-port 6634 ryu/ryu/app/simple_switch_13.py

3. Run the custom topology
sudo python customTopo.py

Watch the results as the script executes the iperf and pingall tests. Enjoy !