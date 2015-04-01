#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def createNetworkTopology():

    #Create a network and add nodes to it

    net = Mininet(controller=RemoteController)

    info( '*** Adding controllers\n' )
    cA = net.addController('cA', controller=RemoteController, ip="127.0.0.1", port=6633)
    cB = net.addController('cB', controller=RemoteController, ip="127.0.0.1", port=6634)

    info( '*** Adding hosts\n' )
    AAh1 = net.addHost('AAh1', ip='10.1.1.1', mac='0A:0A:00:00:00:01')
    AAh2 = net.addHost('AAh2', ip='10.1.1.2', mac='0A:0A:00:00:00:02')
    ABh1 = net.addHost('ABh1', ip='10.1.2.1', mac='0A:0B:00:00:00:01')
    ABh2 = net.addHost('ABh2', ip='10.1.2.2', mac='0A:0B:00:00:00:02')
    BAh1 = net.addHost('BAh1', ip='10.10.10.1', mac='0A:0B:0A:00:00:01')
    BAh2 = net.addHost('BAh2', ip='10.10.10.2', mac='0A:0B:0A:00:00:02')
    BBh1 = net.addHost('BBh1', ip='10.10.20.1', mac='0A:0B:0B:00:00:01')
    BBh2 = net.addHost('BBh2', ip='10.10.20.2', mac='0A:0B:0B:00:00:02')

    info( '*** Adding switches\n' )
    sA = net.addSwitch( 's1', dpid='0000000000000001' )     #Add dpid as string containing a 16 byte (0 padded) hex equivalent of the int dpid 
    sAA = net.addSwitch( 's11', dpid='000000000000000b' )
    sAB = net.addSwitch( 's12', dpid='000000000000000c' )
    sB = net.addSwitch( 's2', dpid='0000000000000002' )
    sBA = net.addSwitch( 's21', dpid='0000000000000015' )
    sBB = net.addSwitch( 's22', dpid='0000000000000016' )
    
    info( '*** Adding links\n' )
    net.addLink(AAh1,sAA)
    net.addLink(AAh2,sAA)
    
    net.addLink(ABh1,sAB)
    net.addLink(ABh2,sAB)
    
    net.addLink(BAh1,sBA)
    net.addLink(BAh2,sBA)
    
    net.addLink(BBh1,sBB)
    net.addLink(BBh2,sBB)

    net.addLink(sAA,sA)
    net.addLink(sAB,sA)
    
    net.addLink(sBA,sB)
    net.addLink(sBB,sB)
    
    net.addLink(sA,sB)


    info('*** Starting network\n')
    net.build()
    sA.start([cA])
    sAA.start([cA])
    sAB.start([cA])
    sB.start([cB])
    sBA.start([cB])
    sBB.start([cB])

    info('\n*** Running pingall\n')
    net.pingAll()

    info('*** Running CLI\n')
    CLI(net)
    info('*** Stopping network')
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    createNetworkTopology()
