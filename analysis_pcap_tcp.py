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
      tcp_header_and_payload_size = len(tcp)
      
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
        "window_size": tcp.win, # window
        "payload_size": packet_data_size,
        "packet_direction": packet_direction,
        "options": {},
        "tcp_header_and_payload_size": tcp_header_and_payload_size
      }

      # add packet info to corresponding tcpflow

      # check for sender initiated tcp flow
      sender_initiated = (source_ip == sender_ip_addr)
      if sender_initiated and packet_direction == SENDER_TO_RECEIVER and packet_info['flags']['syn_set']:
        if (tcp_endpoint not in tcp_flows):
          tcp_flows[tcp_endpoint] = {
            "meta_data": {
              "sender_to_receiver_window_scale": None, # store window scale option from tcp handshake
              "receiver_to_sender_window_scale": None,
            },
            "packets": []
          } # add new flow
      
      tcp_flows[tcp_endpoint]['packets'].append(packet_info)

      # update meta data with window scale (fetch from syn and syn ack packets)
      if packet_info['flags']['syn_set']:
        window_scale = None
        # print("Packet ",str(packet_number), " window scale option detected? ", dpkt.tcp.TCP_OPT_WSCALE in dict(dpkt.tcp.parse_opts(tcp.opts)))
        if (dpkt.tcp.TCP_OPT_WSCALE in dict(dpkt.tcp.parse_opts(tcp.opts))):  
          # print("detected..")
          ws = dict(dpkt.tcp.parse_opts(tcp.opts))[dpkt.tcp.TCP_OPT_WSCALE]
          window_scale = int.from_bytes(ws,byteorder='big')

        if packet_info['flags']['ack_set']: # syn ack -> update receiver to sender window scale
          tcp_flows[tcp_endpoint]['meta_data']['receiver_to_sender_window_scale'] = window_scale
        else: # syn only -> update update sender to receiver window scale 
          tcp_flows[tcp_endpoint]['meta_data']['sender_to_receiver_window_scale'] = window_scale
    # end pcap packet iteration

  # part 1a/b - Display flow info and first two transactions after tcp connection setup (seq num, ack num, receive window size)
  # part 1c - sender throughput
  '''
  (c) The sender throughput. The throughput is the total amount of data sent over time (measured
  in bytes/sec). The time period is the time between sending the first byte to receiving the last
  acknowledgement. For throughput, only consider the packets at the TCP level (including the
  header). You can ignore all other headers and acks.
  '''

  print("\nTotal Number of TCP Flows Detected: ", len(tcp_flows),"\n")


  # map {flow -> {4 tuple -> tuple, 2 transactions -> [], sender throughput -> {}}}
  flow_level_information = {}
  for unique_flow,content in tcp_flows.items():
    # print("the unique flow is ",unique_flow, type(unique_flow))
    flow_level_information[unique_flow] = {}
    # general flow information
    flow_identifier_str = "Flow: Source IP ({}), Source Port ({}), Destination IP ({}), Destination Port ({})".format(
      content['packets'][0]["src_ip"],content['packets'][0]["src_port"],
      content['packets'][0]["dst_ip"],content['packets'][0]["dst_port"])
    flow_level_information[unique_flow]['four_tuple'] = flow_identifier_str
    
    syn_packet = None 
    syn_ack_packet = None 
    ack_packet = None 
    two_transactions = [] # stores two packets after tcp connection
    done_two_trans = False # if done processing two transactions
    # print("First two transactions after the TCP connection setup:\n")

    # flow level statistics
    sender_tcp_bytes_total = 0

    for p in content['packets']:
      # part 1 c computation
      if p['packet_direction'] == SENDER_TO_RECEIVER:
        # print("woooo ", p['packet_num'], "   ", p['tcp_header_and_payload_size'])
        sender_tcp_bytes_total += p['tcp_header_and_payload_size']

      # skip until tcp connection setup successful
      if syn_packet is None or syn_ack_packet is None or ack_packet is None:
        if p['flags']['syn_set'] and p['flags']['ack_set']:
          syn_ack_packet = p
          continue
        elif p['flags']['syn_set']:
          syn_packet = p 
          continue
        elif p['flags']['ack_set']:
          ack_packet = p
          # check for piggy backed data
          if (p['payload_size'] > 0):
            two_transactions.append(p)
          continue
      
      # print("successful process of tcp connection at ", p['packet_num'])
      # tcp connection setup successful
      if not done_two_trans:
        if len(two_transactions) >= 2:
          done_two_trans = True 
          flow_level_information[unique_flow]['two_trans'] = []
          for trans in two_transactions:
            # compute calculated window size
            ws = None # store window scale tcp option
            if trans['packet_direction'] == SENDER_TO_RECEIVER:
              ws = content['meta_data']['sender_to_receiver_window_scale']
            else:
              ws = content['meta_data']['receiver_to_sender_window_scale']
            calculated_window_size = trans['window_size'] * (2 ** ws)
            # display details
            flow_level_information[unique_flow]['two_trans'].append("Packet No: {}\nSequence number: {} Ack number: {} Receive Window size: {}".format(
              trans['packet_num'], trans['seq_num'], trans['ack_num'], calculated_window_size,'\n')
            )
        else:
          two_transactions.append(p)
    # end for loop over tcp packets
  print("=======================================================================")
  for flow_key, flow_contents in flow_level_information.items():
    print(flow_contents['four_tuple'])
    print("\nFirst Two Transactions After TCP Connection Setup:\n")
    for t in flow_contents['two_trans']:
      print(t)
    print("---------------------------------------------------------------------------")

if __name__ == "__main__":
  run_analysis_pcap(r'assignment2.pcap')

