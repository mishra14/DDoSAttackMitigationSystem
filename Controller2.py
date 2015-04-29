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
import csv
import logging

# Logging configuration
logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(logging.INFO)
logging.getLogger("ofp_event").setLevel(logging.WARNING)
#logging.getLogger().addHandler(logging.StreamHandler())


# Receiving requests and passing them to a controller method,
# which handles the request
class RequestHandler(SocketServer.BaseRequestHandler):

    # Set to the handle method in the controller thread
    handler = None

    def handle(self):
        data = self.request.recv(1024)
        RequestHandler.handler(data)


# Simple TCP server spawning new thread for each request
class Server(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


# Client for sending messages to a server
class Client:

    # Initialize with IP + Port of server
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    # Send an arbitrary message given as a string
    # Starts a new thread for sending each message.
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

# The main controller script, extends the already exisiting
# ryu script simple_switch_13
class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    
    # Interval for polling switch statistics
    QUERY_INTERVAL = 2
    # Bandwith threshold in Kbit/s for assuming an attack
    # on a port
    ATTACK_THRESHOLD = 1000
    # Bandwith threshold in Kbit/s for assuming that the
    # attack has stopped after applying an ingress policy
    PEACE_THRESHOLD = 10
    # Number of repeated poll statistics measurements to 
    # assume that the judgement on either "attack over"
    # "host under DDoS attack" is correct.
    SUSTAINED_COUNT = 5

    ##### WRITE COMMENT
    EGRESS_THRESHOLD = 20
    # Specifies if polled switch statistics should reported on stout
    REPORT_STATS = True

    def __init__(self, *args, **kwargs):
        # Monitoring
        super(SimpleMonitor, self).__init__(*args, **kwargs)

        # Set of currently known (assumed) attackers
        self.attackers = set()
        # Sustained counts for the above judgements
        self.sustainedAttacks, self.sustainedPushbackRequests = 0, 0
        # Indicates for each switch to which of its ports we applied an ingress policy
        self.ingressApplied = {"s1": [False, False, False],
                               "s11": [False, False, False],
                               "s12": [False, False, False],
                               "s21": [False, False, False],
                               "s22": [False, False, False],
                               "s2": [False, False, False]}

    # Sustained no attack count for switch/port combinations
        self.noAttackCounts = {"s1":  [0] * 3,
                               "s11": [0] * 3,
                               "s12": [0] * 3,
                               "s21": [0] * 3,
                               "s22": [0] * 3,
                               "s2":  [0] * 3}

        # XXX Add comment
        self.rates = {"s1": [{}, {}, {}], 
                      "s11": [{}, {}, {}], 
                      "s12": [{}, {}, {}], 
                      "s2": [{}, {}, {}], 
                      "s21": [{}, {}, {}], 
                      "s22": [{}, {}, {}]}
        
        # Mapping from switches and ports to
        # attached switchtes/hosts
        self.portMaps = {"s1": ["s11", "s12", "s2"],
                        "s11": ["AAh1", "AAh2", "s1"],
                        "s12": ["ABh1", "ABh2", "s1"],
                        "s21": ["BAh1", "BAh2", "s2"],
                        "s22": ["BBh1", "BBh2", "s2"],
                        "s2": ["s21", "s22", "s1"]}

        # Mapping from datapath ids to switch names
        self.dpids = {0x1: "s1", 
                 0xb: "s11",
                 0xc: "s12",
                 0x2: "s2",
                 0x15: "s21",
                 0x16: "s22"}

        ################################### WRITE COMMENTS
        self.egressApplied = {"s21": [False, set(), 0], 
                              "s22": [False, set(), 0] }
        # Flow datapaths identified by statistics polling
        self.datapaths = {}
        # Last acquired byte counts for each FLOW
        # to calculate deltas for bandwith usage calculation
        self.flow_byte_counts = {}
        # Last acquired byte counts for each PORT
        # to calculate deltas for bandwith usage calculation
        self.port_byte_counts = {}
        # Thread for polling flow and port statistics
        self.monitor_thread = hub.spawn(self._monitor)

        # Pushback state
        # Set of hosts, which we suspect to be victims of an attack originating
        # in the other network
        self.pushbacks = set()
        # Set of hosts in other domain to which we were reported an attack
        self.other_victims = set()

###########################################
# Server Code
###########################################

        # Lock for the set of victims reported by the other server
        
        self.lock = threading.Lock()
        # IP + PORT for the TCP Server on this controller
        ip, port = "localhost", 2001
        # IP + PORT for the TCP Server on the other controller
        ip_other, port_other = "localhost", 2000

        # Handler for incoming requests to the server
        RequestHandler.handler = self.handlePushbackMessage

        # Server instance
        self.server = Server((ip, port), RequestHandler)

        # Initiate server thread
        server_thread = threading.Thread(target=self.server.serve_forever)
        # Server thread will terminate when controller terminates
        server_thread.daemon = True
        server_thread.start()

        # Start client for sending pushbacks to the other server
        self.client = Client(ip_other, port_other)
        self.iterCount = {"s2": 0, "s21": 0, "s22": 0}
    # Handler receipt of a pushback message
    def handlePushbackMessage(self, data):
        victim = data.strip()[len("Pushback attack to "):]
        logging.info("Received pushback message for victim: %s" % victim)
        # Avoid race conditions for pushback messages
        self.lock.acquire()
        try:
            self.other_victims.add(victim)
        finally:
            self.lock.release()

###########################################
# Monitoring Code
###########################################
    # Handler for registering new datapaths
    # Taken from XXX add source
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                #logging.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                #logging.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    # Main function of the monitoring thread
    # Simply polls switches for statistics
    # in the interval given by QUERY_INTERVAL
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(SimpleMonitor.QUERY_INTERVAL)

    # Helper function for polling statistics of a datapath
    # Again, taken from XXX
    def _request_stats(self, datapath):
        #logging.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # Handler for receipt of flow statistics
    # Main entry point for our DDoS detection code.
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        
        domainHosts = ['0b:0a:00:00:00:01', '0b:0a:00:00:00:02', '0b:0b:00:00:00:01', '0b:0b:00:00:00:02']
        
        # The (suspected) set of victims identified by the statistics
        victims = set()

        body = ev.msg.body
        # Get id of datapath for which statistics are reported as int
        dpid = int(ev.msg.datapath.id)
        switch = self.dpids[dpid]

        if SimpleMonitor.REPORT_STATS:
            print "-------------- Flow stats for switch", switch, "---------------"
        csvRates = {switch + "-eth1": 0, switch + "-eth2": 0, switch + "-eth3": 0}
        self.iterCount[switch] += 1
        # Iterate through all statistics reported for the flow
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            # Get in and out port + MAC dest of flow
            in_port = stat.match['in_port']
            out_port = stat.instructions[0].actions[0].port
            eth_dst = stat.match['eth_dst']

            # Check if we have a previous byte count reading for this flow
            # and calculate bandwith usage over the last polling interval
            key = (dpid, in_port, eth_dst, out_port)
            rate = 0
            if key in self.flow_byte_counts:
                cnt = self.flow_byte_counts[key]
                rate = self.bitrate(stat.byte_count - cnt)
            self.flow_byte_counts[key] = stat.byte_count
            if SimpleMonitor.REPORT_STATS:
                print "In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (in_port, eth_dst, out_port, rate)
            csvRates[switch + "-eth" + str(in_port)] += rate
            # Save the bandwith calculated for this flow
            self.rates[switch][in_port - 1][str(eth_dst)] = rate

            # If we find the bandwith for this flow to be higher than
            # the provisioned limit, we mark the corresponding
            # host as potential vicitim
            if rate > SimpleMonitor.ATTACK_THRESHOLD:
                self.noAttackCounts[switch][in_port - 1] = 0
                victim = str(eth_dst)
                if victim in domainHosts:  # if not in domain, ignore it. wait for a pushback request if it's that important
                    victims.add(victim)

        with open("/home/mininet/cis553-project2/" + str(switch) + ".csv", 'a') as csvfile:
            flowwriter = csv.writer(csvfile)
            flowwriter.writerow([self.iterCount[switch], csvRates[switch + "-eth1"], csvRates[switch + "-eth2"], csvRates[switch + "-eth3"]])

        # Calculate no sustained attack counts
        for port in range(len(self.ingressApplied[switch])):
            if not self.ingressApplied[switch][port]:
                continue  # If ingress is not applied, skip

            # If rate for all flows on the links is below safe level,
            # increase the sustained no attack count for this link
            if all(x <= SimpleMonitor.PEACE_THRESHOLD for x in self.rates[switch][port].values()):
                self.noAttackCounts[switch][port] += 1
            else:
                self.noAttackCounts[switch][port] = 0
        
        victims = victims.intersection({'0a:0a:00:00:00:01', '0a:0a:00:00:00:02'})  # only consider the protected hosts
        
        # Handle pushback requests from the other host
        self.dealWithPushbackRequests()

        # Identify the set of victims attacked by hosts located in the other domain
        # and directly apply policies to the attackers in the local domain
        pushbacks = self.dealWithAttackers(victims)
        
        if pushbacks == self.pushbacks and len(pushbacks) > 0:            # Send pushback messages
            self.sustainedPushbackRequests += 1
            logging.debug("Sustained Pushback Count %s" % str(self.sustainedPushbackRequests))
            if self.sustainedPushbackRequests > SimpleMonitor.SUSTAINED_COUNT:
                for victim in pushbacks:
                    self.client.send("Pushback attack to " + victim)
                self.sustainedPushbackRequests = 0
        elif len(pushbacks) > 0:
            self.sustainedPushbackRequests = 0
            self.pushbacks = pushbacks

        for switch in self.egressApplied:
            if self.egressApplied[switch][0]:
                self.egressApplied[switch][2] += 1
                if self.egressApplied[switch][2] > SimpleMonitor.EGRESS_THRESHOLD:
                    self.removeEgress(switch)
                    
        self.checkForIngressRemoval(victims)  # If there are no victims, for a sustained duration, try remove ingress policies

        if SimpleMonitor.REPORT_STATS:
            print "--------------------------------------------------------"
        

    # Handle pushback requests issued by the controller in the other domain
    def dealWithPushbackRequests(self):
        victims = set()
        # Avoid race conditions pertaining to pushbacks
        self.lock.acquire()
        try:
            victims = self.other_victims
            self.other_victims = set()
        finally:
            self.lock.release()
        
        for victim in victims:
            # Identify attackers for the victims
            victimAttackers = self.getAttackers(victim)
            for victimAttacker in victimAttackers:
                attackerSwitch, _ = self.getSwitch(victimAttacker)
                logging.info("Responding to pushback request, applying egress on %s" % attackerSwitch)
                self.applyEgress(victimAttacker)
            
            # logging.info("Responding to pushback request, applying ingress on %s to relieve %s" % (victimAttackers, victim))
            # Apply an ingress policy to each attacker
            # for attacker in victimAttackers:
            #     self.applyIngress(attacker)

    # Identify the set of victims attacked by hosts located in the other domain
    # and directly apply policies to the attackers in the local domain
    def dealWithAttackers(self, victims):
        # Set of victims attacked by the other domain
        pushbacks = set()
        # Set of attackers in the local domain
        attackers = set()
        for victim in victims:
            victimHost, victimSwitch, victimPort = self.getVictim(victim)
            logging.info("Identified victim: MAC %s Host %s Switch %s Port %s" % (victim, victimHost, victimSwitch, victimPort))
            victimAttackers = self.getAttackers(victim)
            logging.info("Attackers for vicim %s: %s" % (victimAttackers, victimHost))
            if not victimAttackers:
                # No attackers identified, thus assume it's originating in the other domain
                pushbacks.add(victim)
            else:
                attackers = attackers.union(victimAttackers)
        
        # Increase the count for confidence in a suspected attack
        # by the identifed attacker set if applicable
        if attackers == self.attackers and len(attackers) > 0:
            self.sustainedAttacks += 1
            logging.debug("Sustained Attack Count %s" % self.sustainedAttacks)

        else:
            # self.sustainedAttacks = 0 XXX Keep?
            self.attackers = attackers

        # If we have exceeded the confidence count for the local attacker
        # set, apply ingress policies to all attackers
        if self.sustainedAttacks > SimpleMonitor.SUSTAINED_COUNT:
            for attacker in self.attackers:
                self.applyIngress(attacker)

        return pushbacks
        
    # Check if the ingress policy should be removed for any port
    def checkForIngressRemoval(self, victims):
        self.sustainedAttacks = 0
        # If the confidence count for no ongoing attack exceeds the provisioned limit
        # check if the bandwith consumption on one of the rate-limited links
        # dropped below a "safe" level and remove ingress policy
        for switch in self.ingressApplied:  # Iterate through all switches/ports
            for port in range(len(self.ingressApplied[switch])):
                # If rate for all flows on the links for this port have been below a safe level
                # for the last couple of statistic readings, remove the ingress policy
                if self.noAttackCounts[switch][port] >= self.SUSTAINED_COUNT and self.ingressApplied[switch][port]:
                    self.removeIngress(self.portMaps[switch][port])

    # 
    def applyIngress(self, attacker, shouldApply=True):
        attackerSwitch, attackerPort = self.getSwitch(attacker)
        if self.ingressApplied[attackerSwitch][int(attackerPort) - 1] == shouldApply:
            return

        ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=0", "ingress_policing_rate=0"
        if shouldApply:
            self.noAttackCounts[attackerSwitch][int(attackerPort) - 1] = 0
            logging.info("Applying ingress filters on %s, on switch %s at port %s" % (attacker, attackerSwitch, attackerPort))
            ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=100", "ingress_policing_rate=40"
        else:
            logging.info("Removing ingress filters on %s, on switch %s at port %s" % (attacker, attackerSwitch, attackerPort))

        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingBurst])
        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ingressPolicingRate])
        self.ingressApplied[attackerSwitch][int(attackerPort) - 1] = shouldApply

    def removeIngress(self, attacker):
        self.applyIngress(attacker, False)

    def applyEgress(self, attacker):
        attackerSwitch, attackerPort = self.getSwitch(attacker)
        self.egressApplied[attackerSwitch][1].add(self.portMaps[attackerSwitch][int(attackerPort) - 1])
        if self.egressApplied[attackerSwitch][0]:
            return

        # egressCommand = ["sudo", "ovs-vsctl", "-O", "openflow13", "--", "set", "Port", attackerSwitch + "-eth3", "qos=@newqos", "--",
        #  "--id=@newqos", "create", "QoS", "type=linux-htb", "queues=0=@q0", "--", "--id=@q0", "create", "Queue",
        #  "other-config:max-rate=40000"]
        egressCommand = ["sudo", "ovs-vsctl", "--", "set", "Port", attackerSwitch + "-eth3", "qos=@newqos", "--",
         "--id=@newqos", "create", "QoS", "type=linux-htb", "queues=0=@q0", "--", "--id=@q0", "create", "Queue",
         "other-config:max-rate=40000"]
        subprocess.call(egressCommand)
        self.egressApplied[attackerSwitch][0] = True
        self.egressApplied[attackerSwitch][2] = 0
        print self.egressApplied

    def removeEgress(self, attackerSwitch):
        if not self.egressApplied[attackerSwitch]:
            return
        subprocess.call(["sudo", "ovs-vsctl", "--", "clear", "port", attackerSwitch + "-eth3", "qos"])
        subprocess.call(["sudo", "ovs-vsctl", "--", "--all", "destroy", "QoS", "--", "--all", "destroy", "Queue"])
        self.egressApplied[attackerSwitch][0] = False
        self.egressApplied[attackerSwitch][2] = 0
        for attacker in self.egressApplied[attackerSwitch][1]:
            self.applyIngress(attacker, shouldApply=True)
        self.egressApplied[attackerSwitch][1] = set()
       



    @staticmethod
    def getVictim(victim):

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

    # Convert from byte count delta to bitrate
    @staticmethod
    def bitrate(bytes):
        return bytes * 8.0 / (SimpleMonitor.QUERY_INTERVAL * 1000)

    # Handle receipt of port traffic statistics
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            key = (ev.msg.datapath.id, stat.port_no)
            
            rx_bitrate, tx_bitrate = 0, 0
            if key in self.port_byte_counts:
                cnt1, cnt2 = self.port_byte_counts[key]
                rx_bitrate = self.bitrate(stat.rx_bytes - cnt1)
                tx_bitrate = self.bitrate(stat.tx_bytes - cnt2)
            self.port_byte_counts[key] = (stat.rx_bytes, stat.tx_bytes)

