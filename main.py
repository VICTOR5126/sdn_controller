import ipaddress
from ryu.base import app_manager 
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4

class SimpleSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(SimpleSDNController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # Stores MAC-to-port mappings
        self.packet_count_host = {}  # Stores packets count per host
        self.packet_count_port = {}  # Stores packets count per port
        self.subnet = ipaddress.IPv4Network('10.0.0.0/24', strict=False)

    def _is_same_subnet(self, ip1, ip2):
        """Checks if two IPs are in the same subnet."""
        return ipaddress.IPv4Address(ip1) in self.subnet and ipaddress.IPv4Address(ip2) in self.subnet

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handles initial connection with a switch."""
        datapath = ev.msg.datapath
        self._install_table_miss_flow(datapath)
    
    def _install_table_miss_flow(self, datapath):
        """Install a table-miss flow entry to handle unmatched packets."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match all packets
        match = parser.OFPMatch()
        # Send unmatched packets to the controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # Create a flow mod message
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match, instructions=inst
        )
        # Send the flow mod message to the switch
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handles packets that are sent to the controller."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Extract packet data
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        
        if eth_pkt:
            self.logger.info("Packet received on port %s", in_port)
            # Handle IPv4 packets
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst

                # Traffic monitoring: Track packets per host
                if src_ip not in self.packet_count_host:
                    self.packet_count_host[src_ip] = 0
                self.packet_count_host[src_ip] += 1

                # Traffic monitoring: Track packets per port
                if in_port not in self.packet_count_port:
                    self.packet_count_port[in_port] = 0
                self.packet_count_port[in_port] += 1

                # Check if source and destination IPs are in the same subnet
                if self._is_same_subnet(src_ip, dst_ip):
                    # Forward the packet
                    actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                else:
                    # Drop the packet if the IPs are in different subnets
                    self.logger.info("Dropping packet between different subnets: %s -> %s", src_ip, dst_ip)
                    return  # Return early without sending any output
                
                # Create and send the packet-out message
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data
                )
                datapath.send_msg(out)
            else:
                self.logger.info("Non-IP packet received on port %s", in_port)
        else:
            self.logger.info("Non-Ethernet packet received on port %s", in_port)
