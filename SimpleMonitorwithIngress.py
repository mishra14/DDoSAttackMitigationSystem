from operator import attrgetter

import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import socket
import threading
import SocketServer
import subprocess

# Receiving requests and passing them to a controller method
class RequestHandler(SocketServer.BaseRequestHandler):

    # Set to the handle method in the controller thread
    handler = None

    def handle(self):
        data = self.request.recv(1024)
        RequestHandler.handler(data)

# TCP server spawning new thread for each request
class Server(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

# Client for sending messages to a server
class Client:

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def send(self, message):
        def do():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.ip, self.port))
            try:
                sock.sendall(message)
                response = sock.recv(1024)
            finally:
                sock.close()

        thread = threading.Thread(target=do)
        thread.daemon = True
        thread.start()
        
class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    
    attackPaths = {}
    attackers = []
    sustainedAttacks, sustainedNoAttacks = 0, 0 
    ingressApplied = {"s1": [False, False, False],
                      "s11": [False, False, False],
                      "s12": [False, False, False],
                      "s21": [False, False, False],
                      "s22": [False, False, False],
                      "s2": [False, False, False]}

    QUERY_INTERVAL = 5
    rates = {"s1": [0,0,0], "s11": [0,0,0], "s12": [0,0,0], "s2": [0,0,0], "s21": [0,0,0], "s22": [0,0,0]}

    def __init__(self, *args, **kwargs):
	# Monitoring
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flows = {}
        self.ports = {}
        self.monitor_thread = hub.spawn(self._monitor)

###########################################
# Server Code
###########################################

	self.msgCount = 0
	self.lock = threading.Lock()
        ip, port = "localhost", 3000

        RequestHandler.handler = self.handlePushbackMessage

        self.server = Server((ip, port), RequestHandler)

	server_thread = threading.Thread(target=self.server.serve_forever)
        # Server thread will terminate when controller terminates
        server_thread.daemon = True
        server_thread.start()

	# Send some test messages
	client = Client(ip, port)
	client.send("Message 1")
	client.send("Message 2")
	client.send("Message 3")

    def handlePushbackMessage(self, data):
	self.lock.acquire()
        try:
            self.msgCount += 1
            # XXX Do something
        finally:
            self.lock.release()
	print "Number of requests counted", self.msgCount, " | Message received: ", data
	if self.msgCount >= 3:
		# XXX Where to shutdown?
		self.server.shutdown()

###########################################
# Monitoring Code
###########################################
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(SimpleMonitor.QUERY_INTERVAL)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        print "----------------------------------------------------------"
        
        victims = set()
        body = ev.msg.body
        dpids = {'1': "s1", 
                 '11': "s11",
                 '12': "s12",
                 '2': "s2",
                 '21': "s21",
                 '22': "s22", }

        portMaps = {"s1": ["s11", "s12", "s2"],
                    "s11": ["AAh1", "AAh2", "s1"],
                    "s12": ["ABh1", "ABh2", "s1"],
                    "s21": ["BAh1", "BAh2", "s2"],
                    "s22": ["BBh1", "BBh2", "s2"],
                    "s2": ["s21", "s22", "s1"]}

        dataPathAttacks = []
        dpid = str(int(ev.msg.datapath.id))
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            key = (ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port)
            cnt = self.flows.get(key, 0)
            rate = self.bitrate(stat.byte_count - cnt)
            self.flows[key] = stat.byte_count 
            print "FLOW Datapath %016x In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port, rate)
            self.rates["s" + str(int(ev.msg.datapath.id))][stat.match['in_port'] - 1] = rate
            in_port = str(stat.match['in_port'])
            out_port = str(stat.instructions[0].actions[0].port)
            if rate > 10000:
                victim = str(stat.match['eth_dst'])
                victims.add(victim)
                inFrom, outTo = portMaps[dpids[dpid]][int(in_port) - 1], portMaps[dpids[dpid]][int(out_port) - 1]
                dataPathAttacks.append((inFrom, outTo))
                    
        for victim in victims:
            victimSwitch, victimPort = self.getVictim(victim)
            print "Victim: MAC %s Switch %s Port %s" % (victim, victimSwitch, victimPort)
            attackers = self.getAttackers(victimSwitch)
            print "Attackers: %s" % attackers
            self.sustainedNoAttacks = 0

            if attackers == self.attackers:
                self.sustainedAttacks += 1
                print "Sustained Attack Count %s" % self.sustainedAttacks
            else:
                self.sustainedAttacks = 0
                self.attackers = attackers
            if self.sustainedAttacks > 10:
                print "Applying ingress filters to %s" % self.attackers 
                for attacker in self.attackers:
                    attackerSwitch, attackerPort = self.getSwitch(attacker)
                    subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, "ingress_policing_burst=100"])
                    subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, "ingress_policing_rate=40"])
                    self.ingressApplied[attackerSwitch][int(attackerPort) - 1] = True
                    
        if len(victims) == 0: # If there are no victims, for a sustained duration, should try removing the ingress
            self.sustainedNoAttacks += 1
            print "Sustained Peace Count %s" % self.sustainedNoAttacks
            if self.sustainedNoAttacks > 10:
                print self.rates  ## Use rates to determine if B/W has gone < 50% or so
                print "Checking if ingress can be removed on any switch"
                for switch in self.ingressApplied:  # Iterate through all switches/ports
                    for port in range(len(self.ingressApplied[switch])):
                        if self.ingressApplied[switch][port] == False: continue  # If ingress is not applied, skip
                        if self.rates[switch][port] > 40: continue  # If the in_rate of that switch/port is > ingress limit, skip
                        attacker = portMaps[switch][port]   # redundant, too lazy
                        attackerSwitch, attackerPort = self.getSwitch(attacker)
                        print "Removing ingress filters on %s at port %s" % (attackerSwitch, attackerPort)
                        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", switch + "-eth" + str(port + 1), "ingress_policing_burst=0"])
                        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", switch + "-eth" + str(port + 1), "ingress_policing_rate=0"])
                        self.ingressApplied[switch][port] = False
        else:
            self.sustainedNoAttacks = 0

        self.attackPaths[dpids[dpid]] = dataPathAttacks
        print "----------------------------------------------------------"
        

    def getVictim(self, victim):
        victimHost = victim[1].upper() + victim[4].upper() + "h" + victim[16]
        victimSwitch = "s"
        if victimHost[0] == "A":
            victimSwitch += "1"
        else:
            victimSwitch += "2"
        if victimHost[1] == "A":
            victimSwitch += "1"
        else:
            victimSwitch += "2"
        victimPort = victimHost[3]
        
        return victimSwitch, victimPort

    def getAttackers(self, victimSwitch):
        attackers = []
        if victimSwitch not in self.attackPaths:
            return []
        for inFrom, outTo in self.attackPaths[victimSwitch]:
            if inFrom[0] != "s" and inFrom != victimSwitch:
                attackers.append(inFrom)
            else:
                attackers.extend(self.getAttackers(inFrom))
        return attackers

    def getSwitch(self, node):
        portMaps = {"s1": ["s11", "s12", "s2"],
                    "s11": ["AAh1", "AAh2", "s1"],
                    "s12": ["ABh1", "ABh2", "s1"],
                    "s21": ["BAh1", "BAh2", "s2"],
                    "s22": ["BBh1", "BBh2", "s2"],
                    "s2": ["s21", "s22", "s1"]}
        for switch in portMaps:
            if node in portMaps[switch]:
                return switch, str(portMaps[switch].index(node) + 1)

    def bitrate(self, bytes):
        return bytes * 8.0 / (SimpleMonitor.QUERY_INTERVAL * 1000)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        #print "----------------------------------------------------------"
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            key = (ev.msg.datapath.id, stat.port_no)
            cnt1, cnt2 = self.ports.get(key, (0,0))
            rx_bitrate = self.bitrate(stat.rx_bytes - cnt1)
            tx_bitrate = self.bitrate(stat.tx_bytes - cnt2)
            self.ports[key] = (stat.rx_bytes, stat.tx_bytes)
        #    print "Datapath %d Port %d RX Bitrate %f TX Bitrate %f"\
        #          % (ev.msg.datapath.id,stat.port_no,rx_bitrate, tx_bitrate)

        #print "----------------------------------------------------------"
