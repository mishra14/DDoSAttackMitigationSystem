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
    
    QUERY_INTERVAL = 2
    ATTACK_THRESHOLD = 5000
    PEACE_THRESHOLD = 40
    SUSTAINED_COUNT = 5

    def __init__(self, *args, **kwargs):
        # Monitoring
        super(SimpleMonitor, self).__init__(*args, **kwargs)

        self.attackers = set()
        self.sustainedAttacks, self.sustainedNoAttacks, self.sustainedPushbackRequests = 0, 0, 0
        self.ingressApplied = {"s1": [False, False, False],
                               "s11": [False, False, False],
                               "s12": [False, False, False],
                               "s21": [False, False, False],
                               "s22": [False, False, False],
                               "s2": [False, False, False]}
        self.rates = {"s1": [{}, {}, {}], 
                      "s11": [{}, {}, {}], 
                      "s12": [{}, {}, {}], 
                      "s2": [{}, {}, {}], 
                      "s21": [{}, {}, {}], 
                      "s22": [{}, {}, {}]}
        self.portMaps = {"s1": ["s11", "s12", "s2"],
                        "s11": ["AAh1", "AAh2", "s1"],
                        "s12": ["ABh1", "ABh2", "s1"],
                        "s21": ["BAh1", "BAh2", "s2"],
                        "s22": ["BBh1", "BBh2", "s2"],
                        "s2": ["s21", "s22", "s1"]}
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

        self.client = Client(ip_other, port_other)

    def handlePushbackMessage(self, data):
        self.lock.acquire()
        print "Received pushback message:", data
        victim = data.strip()[len("Pushback attack to "):]
        try:
            self.other_victims.add(victim)
            print "Pushback requested for ", victim

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
                 0x16: "s22"}
        #domainHosts = ['0a:0a:00:00:00:01', '0a:0a:00:00:00:02', '0a:0b:00:00:00:01', '0a:0b:00:00:00:02']
        domainHosts = ['0b:0a:00:00:00:01', '0b:0a:00:00:00:02', '0b:0b:00:00:00:01', '0b:0b:00:00:00:02']
        
        # Initialize set of victims to the set of victims identified in the other domain
        victims = set()

        dpid = int(ev.msg.datapath.id)
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            in_port = stat.match['in_port']
            out_port = stat.instructions[0].actions[0].port
            eth_dst = stat.match['eth_dst']
            key = (dpid, in_port, eth_dst, out_port)
            rate = 0
            if key in self.flows:
                cnt = self.flows.get(key, 0)
                rate = self.bitrate(stat.byte_count - cnt)
            self.flows[key] = stat.byte_count
            print "FLOW Datapath %016x In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (dpid, in_port, eth_dst, out_port, rate)

            self.rates["s" + str(dpid)][in_port - 1][str(eth_dst)] = rate

            if rate > SimpleMonitor.ATTACK_THRESHOLD:
                victim = str(eth_dst)
                if victim in domainHosts:  # if not in domain, ignore it. wait for a pushback request if it's that important
                    victims.add(victim)
        
        victims = victims.intersection({'0a:0a:00:00:00:01', '0a:0a:00:00:00:02'})  # only consider the protected hosts
        
        #print "OTHER VICTIMS %s" % self.other_victims 
        self.dealWithPushbackRequests()
        pushbacks = self.dealWithAttackers(victims)
        #print "PUSHBACKS %s" % pushbacks
        
        if pushbacks == self.pushbacks and len(pushbacks) > 0:            # Send pushback messages
            self.sustainedPushbackRequests += 1
            print "Sustained Pushback Count %s" % str(self.sustainedPushbackRequests)
            if self.sustainedPushbackRequests > SimpleMonitor.SUSTAINED_COUNT:
                for victim in pushbacks:
                    self.client.send("Pushback attack to " + victim)
                self.sustainedPushbackRequests = 0
        elif len(pushbacks) > 0:
            self.sustainedPushbackRequests = 0
            self.pushbacks = pushbacks

        self.checkForIngressRemoval(victims)  # If there are no victims, for a sustained duration, should try removing the ingress
        print "----------------------------------------------------------"
        
    def dealWithPushbackRequests(self):
        for victim in self.other_victims:
            victimAttackers = self.getAttackers(victim)
            print "Responding to pushback request, applying ingress on %s to relieve %s" % (victimAttackers, victim)
            for attacker in victimAttackers:
                self.applyIngress(attacker)
        self.other_victims = set()

    def dealWithAttackers(self, victims):
        pushbacks = set()
        attackers = set()
        for victim in victims:
            victimHost, victimSwitch, victimPort = self.getVictim(victim)
            print "Victim: MAC %s Host %s Switch %s Port %s" % (victim, victimHost, victimSwitch, victimPort)
            victimAttackers = self.getAttackers(victim)
            print "Attackers: %s" % victimAttackers
            if not victimAttackers:
                # No attackers identified, thus assume it's originating in the other domain
                pushbacks.add(victim)
            else:
                attackers = attackers.union(victimAttackers)
        
        if attackers == self.attackers and len(attackers) > 0:
            self.sustainedAttacks += 1
            print "Sustained Attack Count %s" % self.sustainedAttacks

        else:
            # self.sustainedAttacks = 0 XXX Keep?
            self.attackers = attackers

        if self.sustainedAttacks > SimpleMonitor.SUSTAINED_COUNT:
            for attacker in self.attackers:
                self.applyIngress(attacker)
        
        return pushbacks
        
    def checkForIngressRemoval(self, victims):
        if len(victims) == 0:
            self.sustainedAttacks = 0
            self.sustainedNoAttacks += 1
            print "Sustained Peace Count %s" % self.sustainedNoAttacks
            if self.sustainedNoAttacks > SimpleMonitor.SUSTAINED_COUNT:
                for switch in self.ingressApplied:  # Iterate through all switches/ports
                    for port in range(len(self.ingressApplied[switch])):
                        if not self.ingressApplied[switch][port]:
                            continue  # If ingress is not applied, skip
                        switchInRates = [x <= SimpleMonitor.PEACE_THRESHOLD for x in self.rates[switch][port].values()]
                        isBelowThreshold = reduce(lambda x, y: x and y, switchInRates)
                        if isBelowThreshold:
                            self.removeIngress(self.portMaps[switch][port])
                self.sustainedNoAttacks = 0  # this is there because need to cap the count at some point
        else:
            self.sustainedNoAttacks = 0

    def applyIngress(self, attacker, shouldApply=True):
        attackerSwitch, attackerPort = self.getSwitch(attacker)
        if self.ingressApplied[attackerSwitch][int(attackerPort) - 1] == shouldApply:
            return

        ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=0", "ingress_policing_rate=0"
        if shouldApply:
            print "Applying ingress filters on %s, on switch %s at port %s" % (attacker, attackerSwitch, attackerPort)
            ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=100", "ingress_policing_rate=40"
        else:
            print "Removing ingress filters on %s, on switch %s at port %s" % (attacker, attackerSwitch, attackerPort)

        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingBurst])
        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingRate])
        self.ingressApplied[attackerSwitch][int(attackerPort) - 1] = shouldApply

    def removeIngress(self, attacker):
        self.applyIngress(attacker, False)

    @staticmethod
    def getVictim(victim):
        # XXX Extremely hacky
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

    def getAttackers(self, victim):
        attackers = set()
        for switch in self.rates:
            for port in range(len(self.rates[switch])):
                if victim not in self.rates[switch][port]:  # Not sure if it will ever be the case
                    continue
                if self.rates[switch][port][victim] > SimpleMonitor.ATTACK_THRESHOLD:
                    attacker = self.portMaps[switch][port]
                    if not self.isSwitch(attacker):
                        attackers.add(attacker)
                    
        return attackers

    @staticmethod
    def isSwitch(victim):
        return victim[0] == "s"

    @staticmethod
    def getSwitch(node):
        portMaps = {"s1": ["s11", "s12", "s2"],
                    "s11": ["AAh1", "AAh2", "s1"],
                    "s12": ["ABh1", "ABh2", "s1"],
                    "s21": ["BAh1", "BAh2", "s2"],
                    "s22": ["BBh1", "BBh2", "s2"],
                    "s2": ["s21", "s22", "s1"]}
        for switch in portMaps:
            if node in portMaps[switch]:
                return switch, str(portMaps[switch].index(node) + 1)

    @staticmethod
    def bitrate(bytes):
        return bytes * 8.0 / (SimpleMonitor.QUERY_INTERVAL * 1000)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            key = (ev.msg.datapath.id, stat.port_no)
            cnt1, cnt2 = self.ports.get(key, (0,0))
            rx_bitrate = self.bitrate(stat.rx_bytes - cnt1)
            tx_bitrate = self.bitrate(stat.tx_bytes - cnt2)
            self.ports[key] = (stat.rx_bytes, stat.tx_bytes)
