import netifaces
from os import system


def start_mon_iface():
    iface, mon_mac, initial_interfaces = choose_interface()
    system('sudo airmon-ng start ' + iface)
    final_interfaces = netifaces.interfaces()
    new_interface = list(set(final_interfaces) - set(initial_interfaces))[0]
    return new_interface, mon_mac


def stop_mon_iface():
    system('sudo airmon-ng stop mon0')


def choose_interface():
    initial_interfaces = netifaces.interfaces()

    for count, interface in enumerate(initial_interfaces):
        print(str(count) + ' - ' + interface)

    interface_number = input("Enter interface number: ")

    while not interface_number.isdigit():
        interface_number = input("Enter valid interface number: ")

    while int(interface_number) > len(initial_interfaces):
        interface_number = input("Enter valid interface number: ")

    interface = initial_interfaces[int(interface_number)]

    # return choosen interface name, choosen interface mac, list of all initially available interfaces
    return interface, netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'], initial_interfaces


if __name__ == '__main__':
    if 'mon' in netifaces.interfaces()[-1]:
        print('Monitor Mode Active - Disabling it..')
        system('sudo airmon-ng stop ' + netifaces.interfaces()[-1])

    else:
        print('Choose interface to monitor')
        interface, interface_mac, null = choose_interface()
        system('sudo airmon-ng start ' + interface)
