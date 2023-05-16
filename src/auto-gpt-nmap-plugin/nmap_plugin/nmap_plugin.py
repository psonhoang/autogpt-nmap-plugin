import nmap
# from typing import Any, Dict
# from rich.table import Table

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
__NMAP__FLAGS__ = " ".join(NMAP_HOME_NETWORK_DEFAULT_FLAGS.keys())


# def create_scan_table(*, cli: str) -> Table:
#     """
#     Create a table for the CLI UI
#     :param cli: Full Nmap arguments used on the run
#     :return: Skeleton table, no data
#     """
#     nmap_table = Table(title=f"NMAP run info: {cli}")
#     nmap_table.add_column("IP", justify="right", style="cyan", no_wrap=True)
#     nmap_table.add_column("Protocol", justify="right", style="cyan", no_wrap=True)
#     nmap_table.add_column("Port ID", justify="right", style="magenta", no_wrap=True)
#     nmap_table.add_column("Service", justify="right", style="green")
#     nmap_table.add_column("CPE", justify="right", style="blue")
#     nmap_table.add_column("Advisories", justify="right", style="blue")
#     return nmap_table


# ...


# def fill_simple_table(*, exec_data: str, parsed_xml: Dict[Any, Any]) -> Table:
#     """
#     Convenience method to create a simple UI table with Nmap XML output
#     :param exec_data: Arguments and options used to run Nmap
#     :param parsed_xml: Nmap data as a dictionary
#     :return: Populated tabled
#     """
#     nmap_table = create_scan_table(cli=exec_data)
#     for row_data in parsed_xml:
#         address = row_data['address']
#         ports = row_data['ports']
#         for port_data in ports:
#             nmap_table.add_row(
#                 address,
#                 port_data['protocol'],
#                 port_data['port_id'],
#                 f"{port_data['service_name']} {port_data['service_product']} {port_data['service_version']}",
#                 "\n".join(port_data['cpes']),
#                 ""
#             )
#     return nmap_table


# class OutputParser:
#     """
#     Parse Nmap raw XML output
#     """
#     @staticmethod
#     def parse_nmap_xml(xml: str) -> (str, Any):
#         """
#         Parse XML and return details for the scanned ports
#         @param xml:
#         @return: tuple nmaps arguments, port details
#         """
#         parsed_data = []
#         root = ElementTree.fromstring(xml)
#         nmap_args = root.attrib['args']
#         for host in root.findall('host'):
#             for address in host.findall('address'):
#                 curr_address = address.attrib['addr']
#                 data = {
#                     'address': curr_address,
#                     'ports': []
#                 }
#                 states = host.findall('ports/port/state')
#                 ports = host.findall('ports/port')
#                 for i in range(len(ports)):
#                     if states[i].attrib['state'] == 'closed':
#                         continue  # Skip closed ports
#                     port_id = ports[i].attrib['portid']
#                     protocol = ports[i].attrib['protocol']
#                     services = ports[i].findall('service')
#                     cpe_list = []
#                     service_name = ""
#                     service_product = ""
#                     service_version = ""
#                     for service in services:
#                         for key in ['name', 'product', 'version']:
#                             if key in service.attrib:
#                                 if key == 'name':
#                                     service_name = service.attrib['name']
#                                 elif key == 'product':
#                                     service_product = service.attrib['product']
#                                 elif key == 'version':
#                                     service_version = service.attrib['version']
#                         cpes = service.findall('cpe')
#                         for cpe in cpes:
#                             cpe_list.append(cpe.text)
#                         data['ports'].append({
#                             'port_id': port_id,
#                             'protocol': protocol,
#                             'service_name': service_name,
#                             'service_product': service_product,
#                             'service_version': service_version,
#                             'cpes': cpe_list
#                         })
#                         parsed_data.append(data)
#         return nmap_args, parsed_data


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
