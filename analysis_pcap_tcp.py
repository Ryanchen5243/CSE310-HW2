import datetime
import dpkt
import socket
import struct

def run_analysis_pcap(in_file):
  # count_syn, count_ack, count_other_packet,total_packets  = 0, 0, 0, 0
  tcp_flows = {}
  sender_ip_addr = "130.245.145.12"
  receiver_ip_addr = "128.208.2.198"

  with open (in_file,'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    packet_number = 0 # initialize packet number

    # iterate through pcap object
    for timeStamp, buffer in pcap:
      # print("Timestamp: ",str(timeStamp))
      packet_number += 1 # increment packet number
      eth = dpkt.ethernet.Ethernet(buffer)

      # check ethernet frame has an ip packet
      if not isinstance(eth.data,dpkt.ip.IP):
        print("Ethernet Frame without IP Packet Detected")
        continue

      # unpack ip packet from frame
      ip = eth.data

      # check that its a tcp packet
      if not isinstance(ip.data,dpkt.tcp.TCP):
        print("non TCP packet detected")
        continue

      # extract info for tcp connnection
      source_ip = socket.inet_ntoa(ip.src)
      dest_ip = socket.inet_ntoa(ip.dst)
      source_port = ip.data.sport
      dest_port = ip.data.dport
      protocol = ip.get_proto(ip.p).__name__

      tcp_endpoint = (source_ip, source_port, dest_ip, dest_port, protocol)

      # print("Source ip",source_ip)
      # print("sender ip", sender_ip_addr)

      SENDER_TO_RECEIVER = "sender_to_receiver"
      RECEIVER_TO_SENDER = "receiver_to_sender"
      packet_direction = None
      if source_ip == sender_ip_addr:
        packet_direction = SENDER_TO_RECEIVER
      else:
        packet_direction = RECEIVER_TO_SENDER
      
      # unique TCP flow is identified by (lower ip_addr:port, higher ip_addr:port)
      source_ip_int = struct.unpack("!L",socket.inet_aton(source_ip))[0]
      dest_ip_int = struct.unpack("!L",socket.inet_aton(dest_ip))[0]
      if source_ip_int > dest_ip_int:
        tcp_endpoint = (dest_ip, dest_port, source_ip, source_port, protocol)

      # print("Source IP: ", source_ip, " Dest IP: ", dest_ip)
      # print("TCP Endpoint: ", tcp_endpoint)
      # print("Packet Direction: ",packet_direction)
      
      # add new flow candidate to result
      if tcp_endpoint not in tcp_flows:
        tcp_flows[tcp_endpoint] = []

      # ip payload = tcp
      tcp = ip.data
      # link_layer_header_size = dpkt.ethernet.ETH_HDR_LEN
      # buffer_size = len(buffer)
      # network_layer_header_size = dpkt.ip.IP_HDR_LEN
      packet_data_size = len(tcp.data)
      
      # summarize packet information
      packet_info = {
        "packet_num": packet_number,
        "time_stamp": str(datetime.datetime.utcfromtimestamp(timeStamp)),
        "src_ip": source_ip,
        "dst_ip": dest_ip,
        "src_port": source_port,
        "dst_port": dest_port,
        "seq_num": ip.data.seq,
        "ack_num": ip.data.ack,
        "flags" : {
          "ack_set": bool(ip.data.flags & dpkt.tcp.TH_ACK),
          "syn_set": bool(ip.data.flags & dpkt.tcp.TH_SYN),
          "fin_set": bool(ip.data.flags & dpkt.tcp.TH_FIN)
        },
        "window_size": ip.data.win,
        "payload_size": packet_data_size,
        "packet_direction": packet_direction
      }
      
      # add packet info to corresponding tcpflow
      tcp_flows[tcp_endpoint].append(packet_info)
    # end pcap packet iteration

    # Display
    for tcp_flow,packets in tcp_flows.items():
      print("TCP Flow: ")
      first_packet_in_flow = packets[0]
      print("Source IP Address: {}\nSource Port: {}\nDestination IP Address: {}\nDestination Port: {}".format(
        first_packet_in_flow['src_ip'], first_packet_in_flow['src_port'], first_packet_in_flow['dst_ip'],first_packet_in_flow['dst_port']
      ))
      print()

if __name__ == "__main__":
  run_analysis_pcap(r'assignment2.pcap')

