import ipaddress
import argparse
import sys, os

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
            print('The given file does not exist')
            sys.exit(1)
    else:
        try:
            if '/' in hosts_file:
                # Assuming CIDR notation
                network = ipaddress.ip_network(hosts_file, strict=False)
                hosts.extend(str(ip) for ip in network.hosts())
            else:
                hosts.append(hosts_file)
        except Exception as e:
            print(e)
            print('Error: there is something wrong with the ip you gave')
            sys.exit(1)
        hosts = list(set(hosts))  # unique the hosts
        return hosts

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Take a file of scope and a file of ")  # argparse
    parser.add_argument("scope_file", help="Path to a file containing the full scope can be 1 ip per line or 1 cidr per line")
    parser.add_argument("exclusions_file", help="Path to a file containing the list of exclusions can be 1 ip per line or 1 cidr per line")
    parser.add_argument('-o', default='cidr_clean.txt', help='Outputfile name Default=cidr_clean.txt')
    parser.add_argument('-t', default='cidr', choices=['ips', 'cidr'], help='Type of output you want Cidr notation or just raw IPs Options=[ips,cidr]')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    scope = parse_hosts_file(options.scope_file)
    print('Scope contains {} ips'.format(str(len(scope))))
    exclusions = parse_hosts_file(options.exclusions_file)
    print('Exclusions contains {} ips'.format(str(len(exclusions))))

    scope_exclusions_removed = []

    for ip in scope: # remove invalid ips
        if ip not in exclusions:
            try:
                test = ipaddress.ip_address(ip)
                scope_exclusions_removed.append(ip)
            except ValueError:
                print('Invalid IP address detected from scope skipping: %s' % ip)
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

    if options.t == 'cidr':
        scope_exclusions_removed = [ipaddress.IPv4Address(line) for line in scope_exclusions_removed] # convert the list of strings to a list of ipv4address objects
        scope_exclusions_removed = [ip.with_prefixlen for ip in ipaddress.collapse_addresses(scope_exclusions_removed)] # convert that to cidr

    print('Cleaned list contains {} ips/subnets'.format(str(len(scope_exclusions_removed))))
    with open(options.o, 'a') as f:
        for item in scope_exclusions_removed:
            f.write(item + '\n')
    f.close()
