import ipaddress
import argparse
import sys, os

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

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    scope = parse_hosts_file(args.scope_file)
    print('Scope contains {} ips'.format(str(len(scope))))
    exclusions = parse_hosts_file(args.exclusions_file)
    print('Exclusions contains {} ips'.format(str(len(exclusions))))

    scope_exclusions_removed = []

    for ip in scope:
        if ip not in exclusions:
            scope_exclusions_removed.append(ip)

    print('Cleaned list contains {} ips'.format(str(len(scope_exclusions_removed))))

    with open(args.o, 'a') as f:
        for item in scope_exclusions_removed:
            f.write(item + '\n')
    f.close()

