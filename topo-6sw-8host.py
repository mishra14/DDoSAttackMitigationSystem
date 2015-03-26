"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
	"Simple topology example."
	def __init__( self ):
		"Create custom topo."
		# Initialize topology
		Topo.__init__( self )
		# Add hosts and switches
		AAh1 = self.addHost( 'AAh1' )
		AAh2 = self.addHost( 'AAh2' )
		ABh1 = self.addHost( 'ABh1' )
		ABh2 = self.addHost( 'ABh2' )
		BAh1 = self.addHost( 'BAh1' )
		BAh2 = self.addHost( 'BAh2' )
		BBh1 = self.addHost( 'BBh1' )
		BBh2 = self.addHost( 'BBh2' )
		s1 = self.addSwitch( 's1' )
		s11 = self.addSwitch( 's11' )
		s12 = self.addSwitch( 's12' )
		s2 = self.addSwitch( 's2' )
		s21 = self.addSwitch( 's21' )
		s22 = self.addSwitch( 's22' )
		# Add links
		self.addLink(AAh1,s11)
		self.addLink(AAh2,s11)
		
		self.addLink(ABh1,s12)
		self.addLink(ABh2,s12)
		
		self.addLink(BAh1,s21)
		self.addLink(BAh2,s21)
		
		self.addLink(BBh1,s22)
		self.addLink(BBh2,s22)

		self.addLink(s11,s1)
		self.addLink(s12,s1)
		
		self.addLink(s21,s2)
		self.addLink(s22,s2)
		
		self.addLink(s1,s2)


topos = { 'mytopo': ( lambda: MyTopo() ) }
