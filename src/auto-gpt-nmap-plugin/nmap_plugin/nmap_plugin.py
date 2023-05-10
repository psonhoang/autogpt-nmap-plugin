import nmap

scanner = nmap.PortScanner()


def scan_ports_for(target: str):
    # Scan target for ports in the range 1-65535
    nmScan.scan(target, arguments='-p 1-65535')
    result = []
    for host in nmScan.all_hosts():
        result.append('##########\n')
        resultPerHost = []
        resultPerHost.append('Host : %s (%s)\n' % (host, nmScan[host].hostname()))
        resultPerHost.append('State : %s\n' % nmScan[host].state())
        for proto in nmScan[host].all_protocols():
            resultPerHost.append('----------\n')
            resultPerHost.append('Protocol : %s\n' % proto)

            lport = nmScan[host][proto].keys()
            lport.sort()
            for port in lport:
                resultPerHost.append('port : %s\tstate : %s\n' %
                                     (port, nmScan[host][proto][port]['state']))
        result.append("".join(resultPerHost))
        result.append('##########\n\n')
    return "".join(result)
