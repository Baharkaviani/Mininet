# Route Exercise

"""
This component is for use with the OpenFlow tutorial.
It acts as a Router.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

import pox
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp, echo
from netaddr import *
from pox.lib.revent import *
import pox.lib.packet

class Router (object):
  """
  A Router object is created.
  A Connection object for this router is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

    # message queue
    self.buffer = {}

    # ARP Table
    self.arp_table = {}
    self.arp_table['10.0.1.1'] = '00:00:00:00:00:01'
    self.arp_table['10.0.2.1'] = '00:00:00:00:00:02'
    self.arp_table['10.0.3.1'] = '00:00:00:00:00:03'

    # Rouring Table
    self.routing_table = {}
    self.routing_table['10.0.1.0/24'] = {'interfaceName':'s1-eth1','interfaceAddr':'10.0.1.1','Port': 1}
    self.routing_table['10.0.2.0/24'] = {'interfaceName':'s1-eth2','interfaceAddr':'10.0.2.1','Port': 2}
    self.routing_table['10.0.3.0/24'] = {'interfaceName':'s1-eth3','interfaceAddr':'10.0.3.1','Port': 3}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def handle_ARP_requests (self, packet, packet_in):
    """
    The controller should construct ARP replies and forward them out the appropriate ports.
    """

    ppayload = packet.payload
    requestedIP = str(arp_payload.protodst)

    # We have to check the ARP packet's type,
    # to figure out if it is an ARP_REQUEST or ARP_REPLY.
    if ppayload.opcode == arp.REQUEST:
      log.debug("ARP REQUEST: packet from port {}".format(packet_in.in_port))

      # Now we have to check if the requested ip is in the arp table
      if requestedIP in self.arp_table:

        # make the arp response
        arp_reply = arp()

        # now set ARP structure fields
        arp_reply.hwdst = arp_payload.hwsrc # hardware address of destination
        arp_reply.hwsrc = EthAddr(self.arp_table[requestedIP]) # hardware address of source
        arp_reply.protodst = arp_payload.protosrc #IP address of destination
        arp_reply.protosrc = arp_payload.protodst # IP address of source
        arp_reply.opcode = arp.REPLY # type of arp package

        # make the new packet to send
        newPacket = ethernet()

        # set it's fields
        newPacket.type = newPacket.ARP_TYPE
        newPacket.src = EthAddr(self.arp_table[requestedIP])
        newPacket.dst = arp_payload.hwsrc
        newPacket.payload = arp_reply

        # send the packet to the host
        self.resend_packet(newPacket, packet_in.in_port)
        log.debug("successfull reply packet")

      else:
        log.debug("requestedIP not found!")

    elif ppayload.opcode == arp.REPLY:
      log.debug("ARP REPLY: packet from port {}".format(packet_in.in_port))

      # if the requestedIP in ARP_REPLY is new, add it to ARP table
      if requestedIP not in self.arp_table:
        hwsrc = str(ppayload.hwsrc)

        self.arp_table[requestedIP] = hwsrc
        log.debug("arp table was updated by ip: {} -> mac: {}".format(requestedIP, hwsrc))

  def handle_ICMP_packets (self, packet, packet_in):
    """
    Controller may receive ICMP echo (ping) requests for the router, which it should respond to.
    """
    ppacket = packet.payload

    icmp_request_packet = ppacket.payload
    
    # make new icmp reply to the received icmp request
    if icmp_request_packet.type == 8: # (8 type number is for icmp request)

      icmp_echo_reply_packet = icmp()
      icmp_echo_reply_packet.code = 0
      icmp_echo_reply_packet.type = 0 # (0 type number is for icmp reply)
      icmp_echo_reply_packet.payload = icmp_request_packet.payload

      # make ipv4 header
      ip = ipv4()

      # set it's fields
      ip.srcip = ppacket.dstip
      ip.dstip = ppacket.srcip
      ip.protocol = ipv4.ICMP_PROTOCOL
      ip.payload = icmp_echo_reply_packet

      # make the new packet to send
      newPacket = ethernet()

      # set it's fields
      newPacket.type = ethernet.IP_TYPE
      newPacket.src = ethernet_frame.dst
      newPacket.dst = ethernet_frame.src
      newPacket.payload = ip

      self.resend_packet(newPacket, packet_in.in_port)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Add the new MAC to mac_to_port table
    if str(packet.src) not in self.mac_to_port:
    log.debug("mac_to_port table was updated by mac: {} -> port: {}".format(packet.src, hwsrc))
    self.mac_to_port[str(packet.src)] = packet_in.in_port

    # ARP
    if packet.type == ethernet.ARP_TYPE:
      log.debug("in _handle_PacketIn func: an ARP requeset received.")
      # send to it's function
      self.handle_ARP_requests(packet, packet_in)

    # Static Routing -> handle all ipv4 traffic that comes through the router
    # by forwarding it to the correct subnet.
    elif packet.type == ethernet.IP_TYPE:
      log.debug("in _handle_PacketIn func: an IPv4 packet received.")

      ppayload = packet.payload
      dst_ip = str(ppayload.dstip)
      routable, dst_network = isRoutable (dst_ip)

      if routable:
        # Check if our router's routing_table knows the dst_network
        # and the dst_ip is match to dst_network
        if self.routing_table[str(dst_network)]['interfaceAddr'] == dst_ip:

          if ip_packet.protocol == ipv4.ICMP_PROTOCOL:
            self.handle_ICMP_packets(packet, packet_in)

        else:
          # Route the packet to it's port
          output_port = self.routing_table[dst_network]['Port']
          # ARP if host MAC Address is not present
          if dst_ip not in self.arp_table:
            # Push frame to buffer
            self.buffer[dst_ip] = {'IP_Packet': ppayload, 'DestinationNetwork': dst_network}

            # Construct ARP Packet
            arp_request = arp()

            # now set ARP structure fields
            arp_request.hwdst = EthAddr('00:00:00:00:00:00')
            RouterInterfaceAddr = self.routing_table[dst_network]['interfaceAddr']
            arp_request.hwsrc = EthAddr(self.arp_table[RouterInterfaceAddr])
            arp_request.protodst = IPAddr(dst_ip)
            arp_request.protosrc = IPAddr(self.routing_table[dst_network]['interfaceAddr'])
            arp_request.opcode = arp.REQUEST

            # make the new pavket to send
            newPacket = ethernet()

            # set it's fields
            newPacket.type = newPacket.ARP_TYPE
            newPacket.src = EthAddr(self.arp_table[RouterInterfaceAddr])
            newPacket.dst = EthAddr('FF:FF:FF:FF:FF:FF')
            newPacket.payload = arp_request

            # send the packet
            self.resend_packet(newPacket, output_port)

          if dst_ip in self.arp_table:
            packet.src = EthAddr(self.arp_table[self.routing_table[dst_network]['interfaceAddr']])
            packet.dst = EthAddr(self.arp_table[dst_ip])
            self.resend_packet(packet, output_port)

      # message of ICMP destination unreachable
      else:
        ethernet_frame = packet
        ppacket = packet.payload
        icmp_request_packet = ppacket.payload

        # make an icmp packet
        icmp_echo_reply_packet = icmp()
        icmp_echo_reply_packet.code = 0
        icmp_echo_reply_packet.type = 3 # (3 type number is for icmp destination unreachable)
        icmp_echo_reply_packet.payload = icmp_request_packet.payload

        # make ipv4 header
        ip = ipv4()

        # set it's fields
        ip.srcip = ppacket.dstip
        ip.dstip = ppacket.srcip
        ip.protocol = ipv4.ICMP_PROTOCOL
        ip.payload = icmp_echo_reply_packet

        # make the new packet to send
        newPacket = ethernet()

        # set it's fields
        newPacket.type = ethernet.IP_TYPE
        newPacket.src = ethernet_frame.dst
        newPacket.dst = ethernet_frame.src
        newPacket.payload = ip

        self.resend_packet(newPacket, packet_in.in_port)


  def isRoutable (dst_ip):
    """
    Check if the destination ip address wanted in packet
    is in our routing table or not.
    """

    for r in self.routing_table:
      dst_network = r

      if IPAddress(dst_ip) in IPNetwork(dst_network):
        log.debug("packet is routable!")
        return True, dst_network

    log.debug("packet is not routable!")
    return False, null

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
