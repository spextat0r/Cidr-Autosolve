import ipaddress
import argparse
import sys, os

# so we only need to define them once
classA = ipaddress.IPv4Network(("10.0.0.0", "255.0.0.0"))
classB = ipaddress.IPv4Network(("172.16.0.0", "255.240.0.0"))
classC = ipaddress.IPv4Network(("192.168.0.0", "255.255.0.0"))

def get_ip_class(ipaddr):

    if ipaddr in classA:
        return 'A'
    elif ipaddr in classB:
        return 'B'
    elif ipaddr in classC:
        return 'C'
    else:
        return 'public'

def convert_dashnot_to_ips(inp): # takes string input

    inp = inp.replace(' ', '') # handle the case where a user gives us a - notation ip like "10.10.10.10 - 10.10.20.10"
    tmp = inp.split('-') # split the start and end ips assuming input is "10.10.10.10-10.10.20.10" formatted
    try: # attempt to convert the ips into ipaddress.IPv4Address object if they gave bad input itll error here and we just return blank
        start_ip = ipaddress.IPv4Address(tmp[0])
        end_ip = ipaddress.IPv4Address(tmp[1])
    except ipaddress.AddressValueError:
        print('There is an issue with the ipaddress you gave {}'.format(inp))
        return []
    except Exception as e:
        print(e)
        return []

    if get_ip_class(start_ip) != get_ip_class(end_ip): # ensure the IPs are from the same cidr class
        print('The Start and end IPs are from different IP classes {}'.format(inp))
        return []

    if end_ip < start_ip: # ensure the end ip is bigger than the start ip
        print('EndIP is smaller than StartIP {}'.format(inp))
        return []

    # Generate all IP addresses in the range
    current_ip = start_ip
    ip_list = []

    while current_ip <= end_ip: # get a full list of ips
        ip_list.append(str(current_ip))
        current_ip += 1

    return ip_list

def pub_or_priv(ipaddress_to_check):
    return "Private" if (ipaddress.ip_address(ipaddress_to_check).is_private) else "Public"

def parse_hosts_file(hosts_file):  # parse our host file
    hosts = []
    if os.path.isfile(hosts_file): # ensure the file exists otherwise try it as if they passed an ip or cidr to the command line
        try:
            with open(hosts_file, 'r') as file: # read the file
                for line in file:
                    line = line.strip()
                    if line:
                        try:
                            if '/' in line: # this is so we can have cidr and ips in the same file
                                # Assuming CIDR notation
                                network = ipaddress.ip_network(line, strict=False) # black magic
                                hosts.extend(str(ip) for ip in network.hosts())
                            elif '-' in line: # allow dash notation
                                iplist = convert_dashnot_to_ips(line)
                                if iplist != [] and len(iplist) > 0: # ensure the list is not empty if it is we had an error
                                    for ip in iplist: # append ips to the hosts list
                                        hosts.append(ip)
                                else:
                                    sys.exit(1)
                            else:
                                hosts.append(line)
                        except Exception as e:
                            print(e)
                            print('Error: there is something wrong with the ip in the file line="{}"'.format(line))
                            sys.exit(1)
                file.close()
            hosts = list(set(hosts)) # unique the hosts
            return hosts
        except FileNotFoundError:
            print('The given file does not exist "{}"'.format(hosts_file))
            sys.exit(1)
    else:
        try:
            if '/' in hosts_file:
                # Assuming CIDR notation
                network = ipaddress.ip_network(hosts_file, strict=False)
                hosts.extend(str(ip) for ip in network.hosts())
            elif '-' in hosts_file: # allow dash notation
                iplist = convert_dashnot_to_ips(hosts_file)
                if iplist != [] and len(iplist) > 0: # ensure the list is not empty if it is we had an error
                    for ip in iplist: # append ips to the hosts list
                        hosts.append(ip)
                else:
                    sys.exit(1)
            else:
                hosts.append(hosts_file)
        except Exception as e:
            print(e)
            print('Error: there is something wrong with the ip you gave "{}"'.format(hosts_file))
            sys.exit(1)
        hosts = list(set(hosts))  # unique the hosts
        return hosts

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Take a file of scope and a file of exclusions to output a cleaned scope", formatter_class=argparse.RawTextHelpFormatter, epilog='Accepted IP formats\nSingle: 10.10.10.10\nCidr: 10.10.10.0/24\nSubnet: 10.10.10.0/255.255.255.0\nLine: 10.10.10.0-10.10.11.255')  # argparse
    parser.add_argument("scope_file", help="Path to a file containing the full scope can be 1 ip per line or 1 cidr per line")
    parser.add_argument("exclusions_file", help="Path to a file containing the list of exclusions can be 1 ip per line or 1 cidr per line")
    parser.add_argument('-o', default='cidr_clean.txt', help='Outputfile name Default=cidr_clean.txt')
    parser.add_argument('-t', default='cidr', choices=['ips', 'cidr'], help='Type of output you want Cidr notation or just raw IPs Options=[ips,cidr]')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if os.path.isfile(options.o): # check if the outfile already exists
        conditions = ['y', 'n', 'd']
        yn = input('The output file "{}" already exists do you want to continue Yes, No, Delete the old file? (y/n/d): '.format(options.o)) # figure out what they want to do
        while yn not in conditions: # they gave bad input
            print('Invalid option')
            yn = input('The output file "{}" already exists do you want to continue Yes, No, Delete the old file? (y/n/d): '.format(options.o)) # figure out what they want to do
        if yn.lower() == 'd': # logik
            print('Deleting file "{}"...'.format(options.o))
            os.remove(options.o)
        elif yn.lower() == 'n':
            print('Exiting...')
            sys.exit(1)
        else:
            print('Continuing... this will append new data to "{}"'.format(options.o))


    print('Parsing Scppe...')
    scope = parse_hosts_file(options.scope_file) # parse scope file
    print('Scope contains {} ips'.format(str(len(scope))))
    print('Parsing Exclusions...')
    exclusions = parse_hosts_file(options.exclusions_file) # parse exclusions file
    print('Exclusions contains {} ips'.format(str(len(exclusions))))

    scope_exclusions_removed = []

    for ip in scope: # remove invalid ips
        if ip not in exclusions:
            try:
                test = ipaddress.ip_address(ip)
                scope_exclusions_removed.append(ip)
            except ValueError:
                print('Invalid IP address detected from scope skipping: {}'.format(ip))
                continue

    scope_exclusions_removed = sorted(scope_exclusions_removed, key=ipaddress.IPv4Address)# sort the list of ips
    private = False
    public = False
    for ip in scope_exclusions_removed: # check if there are public and private ips in the scope
        if pub_or_priv(ip) == 'Private':
            private = True
        else:
            public = True

    if public and private:
        print('WARNING: Your scope contains both public and private IP addresses')

    if options.t == 'cidr': # since the scope_exclusions_removed variable is already in a format of just ips we only need to check for -t cidr else do nothing
        scope_exclusions_removed = [ipaddress.IPv4Address(line) for line in scope_exclusions_removed] # convert the list of strings to a list of ipv4address objects
        scope_exclusions_removed = [ip.with_prefixlen for ip in ipaddress.collapse_addresses(scope_exclusions_removed)] # convert that to cidr

    print('Cleaned list contains {} ips/subnets'.format(str(len(scope_exclusions_removed))))
    with open(options.o, 'a') as f: # write to file
        for item in scope_exclusions_removed:
            f.write(item + '\n')
        f.close()
