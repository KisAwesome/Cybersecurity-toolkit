import scapy.all as scapy
import netifaces
import zono.workers
import zono.mac_vendor
import scapy.all as scapy
import sys
import requests

ART = """
▄▄▄ ▄▄▄▄▄▄▄    ▄▄▄ ▄▄    ▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄
█   █       █  █   █  █  █ █       █       █
█   █    ▄  █  █   █   █▄█ █    ▄▄▄█   ▄   █
█   █   █▄█ █  █   █       █   █▄▄▄█  █ █  █
█   █    ▄▄▄█  █   █  ▄    █    ▄▄▄█  █▄█  █
█   █   █      █   █ █ █   █   █   █       █
█▄▄▄█▄▄▄█      █▄▄▄█▄█  █▄▄█▄▄▄█   █▄▄▄▄▄▄▄█
"""


mac_getter = zono.mac_vendor.MacLookup()
worker = zono.workers.Workload(zono.workers.AutoThreads)


def get_vendor(mac_addr):
    if mac_addr.lower() == '28:56:5a:ec:ed:cd':
        return 'Playstation 4'
    return mac_getter.lookup(mac_addr)


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,
                              verbose=False)[0]

    if not answered_list:
        return 0

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    cl = clients_list[-1]
    cl['vendor'] = get_vendor(cl['mac'])
    return cl


def print_result(results_list):
    print("IP\t\t\tMAC Address\t\t\tMac Vendor")
    print("--------------------------------------------------------------------------------------")
    c = 0
    for client in results_list:
        if not client:
            continue
        print(client["ip"] + "\t\t" +
              client["mac"]+'\t\t'+client['vendor'])
        c += 1
    print(f'\n{len(results_list)} hosts scanned {c} up')


def lan_scan(ctx):
    _args = ctx.args
    _r = _args[0].split('-')
    subnet = False
    if '-subnets' in ctx.args:
        subnet = True
        arg_ind = _args.index('-subnets')+1
        if len(_args) < arg_ind:
            return print('Subnets range must be provided')

        _s = _args[arg_ind].split('-')
        if len(_s) > 2:
            print('Subnet range must be two integers seperated by - eg 1-10')

        try:
            sub_rstart = int(_s[0])

        except ValueError:
            print('Subnet range must be two integers seperated by - eg 1-10')
            return

        except IndexError:
            print('Subnet range must be two integers seperated by - eg 1-10')
            return

        try:
            sub_rend = int(_s[1])

        except ValueError:
            print('Subnet range must be two integers seperated by - eg 1-10')
            return

        except IndexError:
            print('Subnet range must be two integers seperated by - eg 1-10')
            return

        if sub_rstart < 0:
            print('Subnet range start cannot be 0')
            return

        if sub_rend > 255:
            print('Subnet range end cannot be greater than 255')
            return

        if sub_rstart >= sub_rend:
            print('Subnet range start cannot be greater than the range end')
            return

    if len(_r) > 2:
        print('Ip range must be two integers seperated by - eg 1-10')

    try:
        rstart = int(_r[0])

    except ValueError:
        print('Ip range must be two integers seperated by - eg 1-10')
        return

    except IndexError:
        print('Ip range must be two integers seperated by - eg 1-10')
        return

    try:
        rend = int(_r[1])

    except ValueError:
        print('Ip range must be two integers seperated by - eg 1-10')
        return

    except IndexError:
        print('Ip range must be two integers seperated by - eg 1-10')
        return

    if rstart < 0:
        print('The range start cannot be 0')
        return

    if rend > 255:
        print('The range end cannot be greater than 255')
        return

    if rstart >= rend:
        print('The range start cannot be greater than the range end')
        return

    results = []
    toscan = []
    gateway = netifaces.gateways()['default'][2][0][:-1]
    if not subnet:
        for ending in range(rstart, rend):
            toscan.append(f'{gateway}{ending}')

    else:
        gateway_2 = gateway[:-3]
        for sub in range(sub_rend, sub_rend):
            for ending in range(rstart, rend):
                toscan.append(f'{gateway_2}{sub}{ending}')

    results = worker.run(toscan, scan)
    print_result(results)


def get_mac(ctx):
    0/0
    s = ctx.args

    if not s:
        print('Ip must be first argument')
        return

    s = s[0]

    if not any(s):
        print('Ip must be first argument')
        return

    mac = scapy.getmacbyip(s)
    if not mac:
        return print('Ip could not be found')
    print(f'Mac for {s} is {mac} the vendor is {get_vendor(mac)}')


def ipinfo(ctx):
    print(ART)
    try:
        query = ctx.args[0]
        url = "http://ip-api.com/json/"+query
    except:
        print('Ip must be first argument,displaying info for your ip')
        url = "http://ip-api.com/json/"

    response2 = requests.get(url)

    values2 = response2.json()

    for i in values2:
        print(i, ':', values2[i])
