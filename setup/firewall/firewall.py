import time
from urllib import urlretrieve
from os import path,mkdir, listdir, unlink
import xml.etree.ElementTree as ElementTree

delay_between_url_fetch=1.0
ip_blocks_target_dir="blocks"
ipv4_deny_aggregate_zone_url = 'http://ipdeny.com/ipblocks/data/aggregated/{0}-aggregated.zone'
ipv6_deny_aggregate_zone_url = 'http://ipdeny.com/ipv6/ipaddresses/aggregated/{0}-aggregated.zone'
traccar_config_file = path.join("../","default.xml")
iptables_custom_chain_name="traccar-protocols"
ipv6_enable=False
countries_to_fetch=[]
clean_output_dir=True

def fetch_country_ip_block(country_iso3_codes):
    if(not(path.exists(ip_blocks_target_dir))):
        mkdir(ip_blocks_target_dir)
    elif clean_output_dir:
        for file in listdir(ip_blocks_target_dir):
            if file.endswith(".zone") or file.endswith(".save") or file.endswith(".sh"):
                unlink(path.join(ip_blocks_target_dir, file))
    for iso3_code in country_iso3_codes:
        try:
            urlretrieve(ipv4_deny_aggregate_zone_url.format(iso3_code),path.join(ip_blocks_target_dir,iso3_code+".zone"))        
        except Exception as error:
            print error
        time.sleep(delay_between_url_fetch) # delay requested by Ipdeny to avoid overloading the service
        if ipv6_enable:
            try:
                urlretrieve(ipv6_deny_aggregate_zone_url.format(iso3_code),path.join(ip_blocks_target_dir,iso3_code+".ipv6.zone"))        
            except Exception as error:
                print error
            time.sleep(delay_between_url_fetch) # delay requested by Ipdeny to avoid overloading the service
            

def update_ip_blocks():
    fetch_country_ip_block(countries_to_fetch)

def get_traccar_protocol_ports():
    ports = {}
    parse_traccar_protocal_ports(ports, traccar_config_file)
    return ports    

def parse_traccar_protocal_ports(destination_ports, configuration_file):
    if(not(path.isabs(configuration_file))):
        configuration_file=path.abspath(configuration_file)

    if not(path.exists(configuration_file)):
        raise Exception("traccar configuration file not found at "+configuration_file);
    
    xml_root_node = ElementTree.parse(configuration_file).getroot();
    for entry in xml_root_node.findall('entry'):
        if entry.attrib['key'] == 'config.default' and entry.text:
            configuration_file_dir = path.dirname(configuration_file);
            parse_traccar_protocal_ports(destination_ports,path.join(configuration_file_dir,entry.text))
        elif entry.attrib['key'].endswith(".port") and entry.text and entry.text.isdigit():
            destination_ports[entry.attrib['key'].replace('.port','')]=str(int(entry.text))

def parse_ip_blocks_files():
    ip_blocks={}
    if(not(path.exists(ip_blocks_target_dir))):
        return
    for file in listdir(ip_blocks_target_dir):
        if file.endswith(".zone"):
            with open(path.join(ip_blocks_target_dir, file),'r') as file_handle:
                ip_blocks[file.replace(".zone","")] = file_handle.readlines()
    return ip_blocks

def write_tables_header(save_file_object, sh_file_object, protocol_ports):
    save_file_object.write("*filter\n:"+iptables_custom_chain_name+" - [0:0]\n")    
    sh_file_object.write("iptables -N "+iptables_custom_chain_name+"\n")
    protocol_rules_count = (len(protocol_ports)/15)+1 # we divide by 15 since a rule can only have a maximum of 15 ports specified
    protocol_rule_index=1
    ports = protocol_ports.values()
    while protocol_rule_index<=protocol_rules_count:
        rule_ports=",".join(ports[((protocol_rule_index-1)*15):(protocol_rule_index*15)])
        if len(rule_ports) == 0:
            break

        rule="{0}-A INPUT -p {1} -m multiport --dports {2} -j {3}\n"
        save_file_object.write(rule.format("","tcp", rule_ports, iptables_custom_chain_name))
        save_file_object.write(rule.format("","udp", rule_ports, iptables_custom_chain_name))
        sh_file_object.write(rule.format("iptables ","tcp", rule_ports, iptables_custom_chain_name))
        sh_file_object.write(rule.format("iptables ","udp", rule_ports, iptables_custom_chain_name))

        protocol_rule_index=protocol_rule_index+1

def generate_iptables_rules():
    ip_blocks = parse_ip_blocks_files();
    protocol_ports = get_traccar_protocol_ports()

    with open(path.join(ip_blocks_target_dir,"combined.save"),"w") as iptables_save:        
        with open(path.join(ip_blocks_target_dir,"combined.sh"),"w") as iptables_sh:
            write_tables_header(iptables_save, iptables_sh, protocol_ports)
            for ip_block in ip_blocks:
                if len(ip_blocks[ip_block]) > 0:
                    with open(path.join(ip_blocks_target_dir,ip_block+".save"),"w") as ipblock_save:
                        with open(path.join(ip_blocks_target_dir,ip_block+".sh"),"w") as ipblock_sh:
                            write_tables_header(ipblock_save, ipblock_sh, protocol_ports)
                            rule="{0}-A {1} -s {2} -j ACCEPT\n"                            
                            for network_ip in ip_blocks[ip_block]:
                                iptables_save.write(rule.format("",iptables_custom_chain_name,network_ip.strip()));
                                iptables_sh.write(rule.format("iptables ",iptables_custom_chain_name,network_ip.strip()));
                                ipblock_save.write(rule.format("",iptables_custom_chain_name,network_ip.strip()));
                                ipblock_sh.write(rule.format("iptables ",iptables_custom_chain_name,network_ip.strip()));
                            # Add a drop rule
                            rule="{0}-A {1} -j DROP\n{2}"
                            ipblock_save.write(rule.format("",iptables_custom_chain_name,"COMMIT\n"));
                            ipblock_sh.write(rule.format("iptables ",iptables_custom_chain_name,""));
            # Add a drop rule
            rule="{0}-A {1} -j DROP\n{2}"
            iptables_save.write(rule.format("",iptables_custom_chain_name,"COMMIT\n"));
            iptables_sh.write(rule.format("iptables ",iptables_custom_chain_name,""));

def get_arguement_parser():
    import argparse
    parser = argparse.ArgumentParser(description='Generate firewall rules to restrict usages of traccar from specific countries.')
    parser.add_argument('-a','--action',metavar='action', required=True, type=str, choices=['u','g','update','generate','ug'],  help='Action to perform: u=updating the ip block lists from ip deny, g=generating the iptable firewall rules in the working directory with files ending with .save and .sh')      
    parser.add_argument('-o','--output', default=ip_blocks_target_dir, metavar='output_dir', type=str,
                        help='Working directory where the ip block files and firewall rules are saved. default: '+ip_blocks_target_dir)
    parser.add_argument('-c', '--countries', default=[],  metavar='country_iso2_codes', type=str, nargs='*',
                        help='Country two letter codes if more than one separated by a space e.g. -c ug tz ke. required if action involves updating the ipblocks ')          
    parser.add_argument('-t', '--traccar', default=traccar_config_file, metavar='traccar', type=str,
                        help='Path to the traccar configuration file. default: '+traccar_config_file)
    parser.add_argument('-f', '--chain', default=iptables_custom_chain_name, metavar='iptables_chain_name', type=str,
                        help='iptables firewall chain name. default: '+iptables_custom_chain_name)
    parser.add_argument('-d','--delay', default=delay_between_url_fetch,  metavar='delay', type=float,
                        help='Delay in seconds between fetching an ip block from ipdeny.com. default: 1')
    parser.add_argument('-i','--ipv6', default=ipv6_enable,  metavar='ipv6', const=False, nargs='?', type=bool,
                        help='Fetch ipv6 country blocks. default: False')
    parser.add_argument('-u','--clean', default=clean_output_dir,  metavar='clean', const=True, nargs='?', type=bool,
                        help='Remove all zone files in output dir before updating ip blocks. default: True')
    return parser

if __name__ == "__main__":    
    import sys
    try:
        program_arguments = get_arguement_parser().parse_args()                
        if (program_arguments.action in ('u','ug','update')) and len(program_arguments.countries) == 0:
            print 'option -c is required when updating ip blocks'
            parser.print_help()
            sys.exit(1)
    except Exception as error:
        print error
        parser.print_help()
        sys.exit(1)
           
    
    ip_blocks_target_dir=program_arguments.output    
    traccar_config_file = program_arguments.traccar
    iptables_custom_chain_name=program_arguments.chain
    ipv6_enable=program_arguments.ipv6
    countries_to_fetch=program_arguments.countries
    clean_output_dir=program_arguments.clean
    
    if program_arguments.action in ('u','ug','update'):
        print 'Updating IP blocks in directory: '+ip_blocks_target_dir
        update_ip_blocks()

    if program_arguments.action in ('g','generate','ug'):
        print 'Generating iptables firewall rules in directory: '+ip_blocks_target_dir
        generate_iptables_rules()
    
    print ' done.'



        

