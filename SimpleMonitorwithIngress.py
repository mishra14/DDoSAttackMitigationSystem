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

    QUERY_INTERVAL = 2
    ATTACK_THRESHOLD = 5000
    PEACE_THRESHOLD = 40
    SUSTAINED_COUNT = 5
    rates = {"s1": [0,0,0], "s11": [0,0,0], "s12": [0,0,0], "s2": [0,0,0], "s21": [0,0,0], "s22": [0,0,0]}

    def __init__(self, *args, **kwargs):
        # Monitoring
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flows = {}
        self.ports = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # Pushback state
        # Set of hosts, which suspect to be victims of an attack originating\
        # in the other network
        self.pushbacks = set()
        # Set of hosts in other domain to which we were reported an attack
        self.other_victims = set()

###########################################
# Server Code
###########################################

        self.msgCount = 0
        self.lock = threading.Lock()
        ip, port = "localhost", 2001
        ip_other, port_other = "localhost", 2000

        RequestHandler.handler = self.handlePushbackMessage

        self.server = Server((ip, port), RequestHandler)

        server_thread = threading.Thread(target=self.server.serve_forever)
        # Server thread will terminate when controller terminates
        server_thread.daemon = True
        server_thread.start()

        # Send some test messages
        self.client = Client(ip_other, port_other)

    def handlePushbackMessage(self, data):
        self.lock.acquire()
        print "Received pushback message:", data
        victim = data.strip()[len("Pushback attack to "):]
        try:
            # HACK
            self.other_victims.add("s2")
            # This does (obviously) not work at the moment
            # because attack tables should carry victim information by id
            #self.other_victims.add(victim)
            #print "Victim is", victim
        finally:
            self.lock.release()

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
        
        body = ev.msg.body
        dpids = {0x1: "s1", 
                 0xb: "s11",
                 0xc: "s12",
                 0x2: "s2",
                 0x15: "s21",
                 0x16: "s22", }

        portMaps = {"s1": ["s11", "s12", "s2"],
                    "s11": ["AAh1", "AAh2", "s1"],
                    "s12": ["ABh1", "ABh2", "s1"],
                    "s21": ["BAh1", "BAh2", "s2"],
                    "s22": ["BBh1", "BBh2", "s2"],
                    "s2": ["s21", "s22", "s1"]}

        # Initialize set of victims to the set of victims identified in the other domain
        victims = set()
        # XXX Should be about this way, see HACK below
        # victims = set(self.other_victims)
        # self.other_victims = set()
        
        # List of all datapaths on which we suspect an attack to happen
        dataPathAttacks = []
        dpid = int(ev.msg.datapath.id)
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            in_port = stat.match['in_port']
            eth_dst = stat.match['eth_dst']
            key = (dpid, in_port, eth_dst, stat.instructions[0].actions[0].port)
            rate = 0
            if key in self.flows:
                cnt = self.flows.get(key, 0)
                rate = self.bitrate(stat.byte_count - cnt)
            self.flows[key] = stat.byte_count
            print "FLOW Datapath %016x In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (dpid, in_port, eth_dst, stat.instructions[0].actions[0].port, rate)
            self.rates["s" + str(dpid)][in_port - 1] = rate
            out_port = stat.instructions[0].actions[0].port
            if rate > SimpleMonitor.ATTACK_THRESHOLD:
                # XXX Should check here if victim is in local network
                victim = str(eth_dst)
                victims.add(victim)
                inFrom, outTo = portMaps[dpids[dpid]][in_port - 1], portMaps[dpids[dpid]][out_port - 1]
                dataPathAttacks.append((inFrom, outTo))
        
        # Set of victims for which we suspect the attack to originate from the other domain
        pushbacks = set()
        
        # XXX Hack
        if self.other_victims:
            victims = set(self.other_victims)
            #self.other_victims = set()
        else:
            # Should be this way
            victims = victims.intersection(set(['0a:0a:00:00:00:01','0a:0a:00:00:00:02']))
        
        for victim in victims:
            victimHost, victimSwitch, victimPort = self.getVictim(victim)
            print "Victim: MAC %s Host %s Switch %s Port %s" % (victim, victimHost, victimSwitch, victimPort)
            attackers = self.getAttackers(victimHost, victimSwitch)
            #attackers = []
            print "Attackers: %s" % attackers
            self.sustainedNoAttacks = 0

            if not attackers:
                # No attackers identified, thus assume it's originating in the other domain
                pushbacks.add(victim)
                #print "No attackers", attackers
            elif attackers == self.attackers:
                self.sustainedAttacks += 1
                print "Sustained Attack Count %s" % self.sustainedAttacks
            else:
                #self.sustainedAttacks = 0 XXX Keep?
                self.attackers = attackers
            # XXX second condition is hack
            # Should move ingress policy into own method and then separate attacks on local and foreign nodes
            # Should remove policies for foreign nodes on message receipt? Otherwise, check that flow to VICTIM(s)
            # is not sustained anymore.
            if self.sustainedAttacks > SimpleMonitor.SUSTAINED_COUNT or self.other_victims:
                print "Applying ingress filters to %s" % self.attackers 
                for attacker in self.attackers:
                    attackerSwitch, attackerPort = self.getSwitch(attacker)
                    subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, "ingress_policing_burst=100"])
                    subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, "ingress_policing_rate=40"])
                    self.ingressApplied[attackerSwitch][int(attackerPort) - 1] = True
        
        self.other_victims = set()
        # XXX Add sustained count
        if pushbacks == self.pushbacks:
            # Send pushback messages
            for victim in pushbacks:
                self.client.send("Pushback attack to " + victim)
        else:
           self.pushbacks = pushbacks

        if len(victims) == 0: # If there are no victims, for a sustained duration, should try removing the ingress
            self.sustainedAttacks = 0
            self.sustainedNoAttacks += 1
            print "Sustained Peace Count %s" % self.sustainedNoAttacks
            if self.sustainedNoAttacks > SimpleMonitor.SUSTAINED_COUNT:
                ## Use rates to determine if B/W has gone < 50% or so
                for switch in self.ingressApplied:  # Iterate through all switches/ports
                    for port in range(len(self.ingressApplied[switch])):
                        if self.ingressApplied[switch][port] == False: continue  # If ingress is not applied, skip
                        if self.rates[switch][port] > SimpleMonitor.PEACE_THRESHOLD: continue  # If the in_rate of that switch/port is > ingress limit, skip
                        attacker = portMaps[switch][port]   # redundant, too lazy
                        attackerSwitch, attackerPort = self.getSwitch(attacker)
                        print "Removing ingress filters on %s at port %s" % (attackerSwitch, attackerPort)
                        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", switch + "-eth" + str(port + 1), "ingress_policing_burst=0"])
                        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", switch + "-eth" + str(port + 1), "ingress_policing_rate=0"])
                        self.ingressApplied[switch][port] = False
                        ## XXX Keep?
                        self.sustainedNoAttacks = 0
        else:
            self.sustainedNoAttacks = 0

        self.attackPaths[dpids[dpid]] = dataPathAttacks
        print "----------------------------------------------------------"
        

    def getVictim(self, victim):
        # XXX Bit hacky
        if victim == "s2":
            return "s1", "s2", 3
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
        
        return victimHost, victimSwitch, victimPort

    def getAttackers(self, victim, victimSwitch):
        attackers = []
        if victimSwitch not in self.attackPaths:
            return []
        print "Paths", victimSwitch, self.attackPaths[victimSwitch]
        for inFrom, outTo in self.attackPaths[victimSwitch]:
            if not self.isSwitch(inFrom) and inFrom != victim:
                attackers.append(inFrom)
            elif outTo == victim:
                attackers.extend(self.getAttackers(victimSwitch, inFrom))
        return attackers

    def isSwitch(self, victim):
        return victim[0] == "s"

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
