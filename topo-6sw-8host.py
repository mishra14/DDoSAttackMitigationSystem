#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def createNetworkTopology():

    "Create a network and add nodes to it."

    net = Mininet( controller=Controller, link=TCLink )

    info( '*** Adding controller\n' )
    net.addController( 'c1' )
    net.addController( 'c2' )

    info( '*** Adding hosts\n' )
    AAh1 = net.addHost( 'AAh1' ,ip='10.1.1.1')
    AAh2 = net.addHost( 'AAh2' ,ip='10.1.1.2')
    ABh1 = net.addHost( 'ABh1' ,ip='10.1.2.1')
    ABh2 = net.addHost( 'ABh2' ,ip='10.1.2.2')
    BAh1 = net.addHost( 'BAh1' ,ip='10.10.10.1')
    BAh2 = net.addHost( 'BAh2' ,ip='10.10.10.2')
    BBh1 = net.addHost( 'BBh1' ,ip='10.10.20.1')
    BBh2 = net.addHost( 'BBh2' ,ip='10.10.20.2')

    info( '*** Adding switches\n' )
    sA = net.addSwitch( 's1' )
    sAA = net.addSwitch( 's11' )
    sAB = net.addSwitch( 's12' )
    sB = net.addSwitch( 's2' )
    sBA = net.addSwitch( 's21' )
    sBB = net.addSwitch( 's22' )
    
    info( '*** Adding links\n' )
    net.addLink(AAh1,sAA,bw=2, delay='2ms',max_queue_size=5)
    net.addLink(AAh2,sAA,bw=2, delay='2ms',max_queue_size=5)
    
    net.addLink(ABh1,sAB,bw=2, delay='2ms',max_queue_size=5)
    net.addLink(ABh2,sAB,bw=2, delay='2ms',max_queue_size=5)
    
    net.addLink(BAh1,sBA,bw=2, delay='2ms',max_queue_size=5)
    net.addLink(BAh2,sBA,bw=2, delay='2ms',max_queue_size=5)
    
    net.addLink(BBh1,sBB,bw=2, delay='2ms',max_queue_size=5)
    net.addLink(BBh2,sBB,bw=2, delay='2ms',max_queue_size=5)

    net.addLink(sAA,sA, bw=5, delay='1ms',max_queue_size=10)
    net.addLink(sAB,sA, bw=5, delay='1ms',max_queue_size=10)
    
    net.addLink(sBA,sB, bw=5, delay='1ms',max_queue_size=10)
    net.addLink(sBB,sB, bw=5, delay='1ms',max_queue_size=10)
    
    net.addLink(sA,sB,bw=10, delay='0ms',max_queue_size=20)


    info( '*** Starting network\n')
    net.start()

    info( '*** Running CLI\n' )
    CLI( net )

    info( '*** Stopping network' )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    createNetworkTopology()
