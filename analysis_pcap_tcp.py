import datetime
import dpkt
import socket
import struct

def run_analysis_pcap(in_file):
  tcp_flows = {} # stores all (sender-initiated) tcp flows
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

      # ip payload = tcp
      tcp = ip.data
      # link_layer_header_size = dpkt.ethernet.ETH_HDR_LEN
      # buffer_size = len(buffer)
      # network_layer_header_size = dpkt.ip.IP_HDR_LEN
      packet_data_size = len(tcp.data)
      
      # compute window size -> handle cases
      # if syn ack packet (contains negotiated window scaling)
      if (bool(ip.data.flags & dpkt.tcp.TH_SYN) and bool(ip.data.flags & dpkt.tcp.TH_ACK) and dpkt.tcp.TCP_OPT_WSCALE in tcp.opts):
        # print("window scale factor detected...")
        # print(packet_info['window_size'] * (2 ** tcp.opts[dpkt.tcp.TCP_OPT_WSCALE]))
        for op,op_data in dpkt.tcp.parse_opts(tcp.opts):
          if op == dpkt.tcp.TCP_OPT_WSCALE:
            # print("detected",int.from_bytes(op_data,byteorder="big"))
            print(2 ** int.from_bytes(op_data,byteorder="big"))
        packet_info['window_size'] = None

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
        "window_size": tcp.win,
        "payload_size": packet_data_size,
        "packet_direction": packet_direction,
        "options": {}
      }


        # print(tcp.opts[dpkt.tcp.TCP_OPT_WSCALE]) 
      
      # add packet info to corresponding tcpflow

      # check for sender initiated tcp flow
      sender_initiated = (source_ip == sender_ip_addr)
      if sender_initiated and packet_direction == SENDER_TO_RECEIVER and packet_info['flags']['syn_set']:
        if (tcp_endpoint not in tcp_flows):
          tcp_flows[tcp_endpoint] = [] # add new flow
      
      tcp_flows[tcp_endpoint].append(packet_info)

    # end pcap packet iteration

  # Display
  print("\nTotal Number of TCP Flows: ", len(tcp_flows),"\n")
  print("------------------------------------------------------------------------------------")
  for tcp_flow,packets in tcp_flows.items():
    print("TCP Flow: ")
    # Display (source port, source IP address, destination port, destination IP address)
    first_packet_in_flow = packets[0]
    print("Source IP Address: {}\nSource Port: {}\nDestination IP Address: {}\nDestination Port: {}".format(
      first_packet_in_flow['src_ip'], first_packet_in_flow['src_port'], first_packet_in_flow['dst_ip'],first_packet_in_flow['dst_port']
    ))
    print()
    # first two transactions after connection setup, sequence number, ack number, and receive window size
    syn_packet = None 
    syn_ack_packet = None 
    ack_packet = None 
    num_transactions_after_setup = 0
    calculated_window_size = 0 # adjust packet data
    print("After TCP Handshake... Sender packets are as follows")
    for p in packets:
      # skip until tcp connection setup successful
      if syn_packet is None or syn_ack_packet is None or ack_packet is None:
        if p['flags']['syn_set'] and p['flags']['ack_set']:
          syn_ack_packet = p 
        elif p['flags']['syn_set']:
          syn_packet = p 
        elif p['flags']['ack_set']:
          ack_packet = p
          # check for piggy backed data
          if (p['payload_size'] > 0):
            print("Packet No: {}\nSequence number: {} Ack number: {} Receive Window size: {}".format(
              p['packet_num'], p['seq_num'], p['ack_num'], p['window_size']
            ))
            num_transactions_after_setup += 1
        continue
      # tcp connection setup successful
      # Sequence number, Ack number, and Receive Window size.
      if num_transactions_after_setup == 2:
        break
      print("Packet No: {}\nSequence number: {} Ack number: {} Receive Window size: {}".format(
        p['packet_num'], p['seq_num'], p['ack_num'], p['window_size']
      ))
      num_transactions_after_setup += 1

    if (syn_packet is None or syn_ack_packet is None or ack_packet is None):
      print("An error occured detecting tcp handshake")
    print("\n------------------------------------------------------------------------------------\n")

if __name__ == "__main__":
  run_analysis_pcap(r'assignment2.pcap')

