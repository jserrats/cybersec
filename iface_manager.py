import netifaces
from os import system


def start_mon_iface():
    iface, mon_mac = choose_interface()
    system('sudo airmon-ng start ' + iface)
    return 'mon0', mon_mac


def stop_mon_iface():
    system('sudo airmon-ng stop mon0')


def choose_interface():
    interfaces = netifaces.interfaces()

    for count, interface in enumerate(interfaces):
        print(str(count) + ' - ' + interface)

    interface_number = input("Enter interface number: ")

    while not interface_number.isdigit():
        interface_number = input("Enter valid interface number: ")

    while int(interface_number) > len(interfaces):
        interface_number = input("Enter valid interface number: ")

    interface = interfaces[int(interface_number)]

    return interface, netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']


def get_ifaces():
    return netifaces.interfaces()


if __name__ == '__main__':
    if 'mon0' in get_ifaces():
        print('Monitor Mode Active - Disabling it..')
        system('sudo airmon-ng stop mon0')

    else:
        print('Choose interface to monitor')
        interface, interface_mac = choose_interface()
        system('sudo airmon-ng start ' + interface)
