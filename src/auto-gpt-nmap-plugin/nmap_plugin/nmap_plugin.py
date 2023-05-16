import nmap
import shlex
# Convert the args for proper usage on the CLI
NMAP_HOME_NETWORK_DEFAULT_FLAGS = {
    '-n': 'Never do DNS resolution',
    '-sS': 'TCP SYN scan, recommended',
    '-p-': 'All ports',
    '-sV': 'Probe open ports to determine service/version info',
    '-O': 'OS Probe. Requires sudo/ root',
    '-T4': 'Aggressive timing template',
    '-PE': 'Enable this echo request behavior. Good for internal networks',
    '--version-intensity 5': 'Set version scan intensity. Default is 7',
    '--disable-arp-ping': 'No ARP or ND Ping',
    '--max-hostgroup 20': 'Hostgroup (batch of hosts scanned concurrently) size',
    '--min-parallelism 10': 'Number of probes that may be outstanding for a host group',
    '--osscan-limit': 'Limit OS detection to promising targets',
    '--max-os-tries 1': 'Maximum number of OS detection tries against a target',
    '-oX -': 'Send XML output to STDOUT, avoid creating a temp file'
}
__NMAP__FLAGS__ = shlex.split(" ".join(NMAP_HOME_NETWORK_DEFAULT_FLAGS.keys()))

nmScan = nmap.PortScanner()


def scan_ports_for(target: str):
    # Scan target for ports in the range 1-65535
    nmScan.scan(target, arguments=__NMAP__FLAGS__)
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
