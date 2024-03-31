import dpkt
import socket, struct

def run_analysis_pcap(in_file):
  count_syn, count_ack, count_other_packet,total_packets  = 0, 0, 0, 0
  total_num_flows = 0

  with open (r'assignment2.pcap','rb') as f:
    pcap = dpkt.pcap.Reader(f)
    # store tcp flows 
    tcp_flows = {} # key is 5-tuple

    # iterate through pcap object
    for timeStamp, buffer in pcap:
      # print("Timestamp: ",str(timeStamp))
      eth = dpkt.ethernet.Ethernet(buffer)

      # unpack ethernet frame
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

      source_ip = socket.inet_ntoa(ip.src)
      dest_ip = socket.inet_ntoa(ip.dst)
      source_port = ip.data.sport
      dest_port = ip.data.dport
      protocol = ip.get_proto(ip.p).__name__

      tcp_endpoint = (source_ip, source_port, dest_ip, dest_port, protocol)
      # normalize the tcp_endpoint of form (lower ip_addr:port, higher ip_addr:port)
      # convert ip address to int for comparison
      source_ip_int = struct.unpack("!L",socket.inet_aton(source_ip))[0]
      dest_ip_int = struct.unpack("!L",socket.inet_aton(dest_ip))[0]
      if source_ip_int > dest_ip_int:
        tcp_endpoint = (dest_ip, dest_port, source_ip, source_port, protocol)

      if (ip.data.flags == dpkt.tcp.TH_SYN):
        print("SYN detected!")
        count_syn += 1
      elif (ip.data.flags == dpkt.tcp.TH_ACK): # Ack detection
        # print("ACK detected!")
        count_ack += 1
      else:
        count_other_packet += 1
      if tcp_endpoint not in tcp_flows:
        tcp_flows[tcp_endpoint] = []

      # add packet to tcp_flows
      tcp_flows[tcp_endpoint].append(buffer)
      total_packets += 1
    # end pcap packet iteration

    # Display
    print("Total Syn: ", count_syn)
    print("Total Ack", count_ack)
    print("Total other pakcet",count_other_packet)
    print("Total Num Packets",total_packets)
if __name__ == "__main__":
  run_analysis_pcap()

