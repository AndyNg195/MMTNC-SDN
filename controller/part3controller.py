from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

class Part3Controller(object):
    def __init__ (self, connection):
        print (connection.dpid)
        self.connection = connection
        connection.addListeners(self)
        
        if (connection.dpid == 1):
            self.s1_setup()
        elif (connection.dpid == 2):
            self.s2_setup()
        elif (connection.dpid == 3):
            self.s3_setup()
        elif (connection.dpid == 21):
            self.cores21_setup()
        elif (connection.dpid == 31):
            self.dcs31_setup()
        else:
            print ("UNKNOWN SWITCH")
            exit(1)

    def s1_setup(self):
        self._allow_all()

    def s2_setup(self):
        self._allow_all()

    def s3_setup(self):
        self._allow_all()

    def cores21_setup(self):
        # Block rules should be added first with highest priority
        self._block()
        # Then add specific routing rules
        self._internal_to_external()
        # Finally, add the default flood rule with lowest priority
        self._allow_all()

    def dcs31_setup(self):
        self._allow_all()

    def _allow_all(self, act=of.ofp_action_output(port=of.OFPP_FLOOD)):
        self.connection.send(of.ofp_flow_mod(action=act, priority=1))

    def _block(self):
        # Block ICMP from hnotrust to all other hosts
        for dest in ['h10', 'h20', 'h30', 'serv1']:
            block_icmp = of.ofp_flow_mod(
                priority=100,  # Higher priority than routing rules
                match=of.ofp_match(
                    dl_type=0x800,  # IPv4
                    nw_proto=pkt.ipv4.ICMP_PROTOCOL,
                    nw_src=IPAddr(IPS['hnotrust']),
                    nw_dst=IPAddr(IPS[dest])
                )
            )
            self.connection.send(block_icmp)

        # Block all IP traffic from hnotrust to serv1
        block_to_serv = of.ofp_flow_mod(
            priority=100,  # Higher priority than routing rules
            match=of.ofp_match(
                dl_type=0x800,  # IPv4
                nw_src=IPAddr(IPS['hnotrust']),
                nw_dst=IPAddr(IPS['serv1'])
            )
        )
        self.connection.send(block_to_serv)

    def _internal_to_external(self):
        # Map of hosts to their corresponding ports on cores21
        host_ports = {
            'h10': 1,
            'h20': 2,
            'h30': 3,
            'serv1': 4,
            'hnotrust': 5
        }

        # Add specific routing rules for each host
        for host, port in host_ports.items():
            self.connection.send(of.ofp_flow_mod(
                action=of.ofp_action_output(port=port),
                priority=10,  # Higher than flood, lower than block
                match=of.ofp_match(
                    dl_type=0x800,  # IPv4
                    nw_dst=IPAddr(IPS[host])
                )
            ))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp
        print("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)