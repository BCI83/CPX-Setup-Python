#!/usr/bin/env python3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import platform, subprocess, os, re, socket, shutil, requests

ostest = platform.platform()
current_hostname = socket.gethostname()
setup_config_file = "/symphony/setup-config"

###################################################################################################
###                                 Functions defined here:                                     ###
###################################################################################################
def ASCII():
    clear()
    print(''' ____                        _ 
/ ___| _   _ _ __ ___  _ __ | |__   ___  _ __  _   _ 
\___ \| | | | '_ ' _ \| '_ \| '_ \ / _ \| '_ \| | | | 
 ___) | |_| | | | | | | |_) | | | | (_) | | | | |_| | 
|____/ \__, |_| |_| |_| .__/|_| |_|\___/|_| |_|\__, | 
  ____ |___/_  __    _|_|       _              |___/ 
 / ___|  _ \ \/ /   / ___|  ___| |_ _   _ _ __ 
| |   | |_) \  /    \___ \ / _ \ __| | | | '_ \ 
| |___|  __//  \     ___) |  __/ |_| |_| | |_) | 
 \____|_|  /_/\_\   |____/ \___|\__|\__,_| .__/ 
                                         |_|
''')

def clear():
    if ostest[0] == 'W': # Then Windows 
        os.system('cls')
    else: # Assume Linux / Mac
        os.system('clear')

def question(Qtext, *options):
    error_message=""
    while True:
        ASCII()
        if error_message != "":
            print(error_message)
        print(Qtext + '\n')        
        for i, option in enumerate(options, start=1):
            if i != "":
                print(f'{i}: {option}')
        if Qtext == "You will need the following information to hand before proceeding:":
            print("---------------------------------------------------------------------\nDo you have all of the required information above?")
            if yn() == "Y":
                break
            else:
                print("\nAborting as 'No' was indicated, this session will now disconnect\n\nSetup will resume when you next log in")
                input("\nHit Enter to continue...")               
                os.system('pkill -KILL -u symphony')
        else:
            answer = input('\nEnter the corresponding number: ')            
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return int(answer)                
            else:
                error_message = "\nERROR: '"+answer+"' is not a valid selection, try again\n"

def yn():
    while True:
        q = input("\ny or n ? : ")
        if q.lower().startswith("y"):
            return "Y"
        elif q.lower().startswith("n"):
            return "N"
        elif q.lower().startswith("q"):
            quit()
        else:
            print("not a valid response, please indicate either y/yes or n/no")

def valid_ip(type_text):
    while True:
        ip = input("Please enter the "+type_text+": ")
        if re.match(r"^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$", ip):
            print("")
            return ip
        else:
            print("That was not a valid IP, please try again")

def valid_sn():
    while True:
        sn = input("\nEnter the subnet mask: /")
        if sn.startswith('/'):
            sn = sn[1:]
        if len(sn) == 1 or len(sn) == 2:
            if 20 <= int(sn) <= 30:
                return sn
            else:
                print("Not a valid subnet mask, please try again")

def valid_hostname():
    while True:
        hn = input("Enter the hostname: ")
        if re.match(r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$", hn):
            return hn

        else:
            print("Not a valid hostname, please try again")
            print("(Only use a-z, A-Z, 0-9, - and . (hyphen and decimal-point))")

def validate_proxy_address(proxy_address):
    pattern = r'^(http|https)://([\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$'
    match = re.match(pattern, proxy_address)
    if match:
        address = match.group(2)
        port = match.group(3)
        # Check if the address is an IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', address):
            address_type = "IP"
        else:
            address_type = "Host"
        return True, address_type, address, port
    else:
        return False, None, None, None, None

def update_line_containing(search_string, new_value, setup_config_file):
    with open(setup_config_file, 'r') as file:
        lines = file.readlines()
    with open(setup_config_file, 'w') as file:
        for line in lines:
            if search_string in line:
                line = f"{new_value}\n"
            file.write(line)

def update_line_starting(search_string, new_value, setup_config_file):
    with open(setup_config_file, 'r') as file:
        lines = file.readlines()
    with open(setup_config_file, 'w') as file:
        for line in lines:
            if line.startswith(search_string):
                line = f"{new_value}\n"
            file.write(line)

def update_word(search_string, new_value, setup_config_file):
    with open(setup_config_file, 'r') as file:
        lines = file.readlines()
    with open(setup_config_file, 'w') as file:
        for line in lines:
            if search_string in line:
                line = line.replace(search_string, new_value)
            file.write(line)

def copy_file(source_file, destination_file):
    shutil.copyfile(source_file, destination_file)

def backup_original(backup_file):
    if check_file(backup_file+".orig") == "N":
        copy_file(backup_file, backup_file+".orig")
        print(backup_file+" file backed up successfully\n")
    else:
        print(backup_file+" backup_original file already exists\n")

def enter_to_cont():
    input("\nHit Enter to continue...")

def valid_port():    
    while True:
        port_input = input("First, enter the port number: ")
        # Check if the input matches the pattern of a valid port number
        if re.match(r'^\d+$', port_input):
            pn = int(port_input)
            # Check if the port number is within the valid range
            if 0 <= pn <= 65535:               
                return  # Valid port number, exit the function
        print("Not a valid port")
        print("Ports are an integer from 0 to 65535")

def check_file(path):
    if os.path.exists(path):
        return "Y"
    else:
        return "N"
    
def certificate(cert_name):
    while True:
        ASCII()
        test_path = input("Enter the absolute path to the (DER or PEM encoded) "+cert_name+"\n( For example: /home/symphony/ca_root.crt )\n\n:")
        if check_file(test_path) == "Y":
            return test_path
        else:
            print("\nNo file found at "+test_path+"\nPlease try again.\n")
            enter_to_cont()

def get_val(search_string, file_to_search = setup_config_file):
    with open(file_to_search, 'r') as file:
        content = file.read()
        pattern = r'(?<=' + search_string + r')(.*)'
        match = re.search(pattern, content)        
        if match:
            found_val = match.group(1).strip().replace(' ', '')
            return found_val
        else:
            return "NOT FOUND"

def ping(server, var_line):
    result = subprocess.run(['ping', '-c', '1', server], capture_output=True, text=True)
    if result.returncode == 0:
        update_line_starting(var_line, var_line+" OK", setup_config_file)
    else:
        if server == gw:
            ping_gw_error = "ERROR: Unable to ping to default gateway, which usually means one of two things\n\nSelect the option which best describes your situation:"
            ping_gw_opt1 = "PING/ICMP has been disabled/blocked at the network level, so continue the setup"
            ping_gw_opt2 = "There may be a mistake in the supplied network settings, restart this setup"
            ping_gw_ans = question(ping_gw_error, ping_gw_opt1, ping_gw_opt2)
            if ping_gw_ans == 2:
                return "restart_setup"
        update_line_starting(var_line, var_line+" Failed", setup_config_file)
        
def check_server(url):
    short_name = url.split(".")[0].split("//")[1]
    try:
        wget_command = f'wget --spider --no-check-certificate {url}'
        wget_process = subprocess.Popen(wget_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        wget_output = wget_process.communicate()
        if wget_process.returncode == 0:
            wget_result = "OK"
        else:
            if short_name == "cloud5":
                wget_result = "File_not_found_(Expected_for_cloud5)"
            else:
                wget_result = "Fail"
        update_line_starting("wget_"+short_name+":","wget_"+short_name+": "+wget_result, setup_config_file)
    except Exception as e:
        pass
    
    try:
        curl_command = f'curl -L -k --write-out %{{http_code}} --silent --output /dev/null  {url}'
        curl_process = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        curl_output, curl_error = curl_process.communicate()
        response_code = curl_output.decode().strip()
        if response_code == "200":
            curl_result = "OK"
        elif response_code == "302":
            curl_result = "OK"
        elif response_code == "404":
            curl_result = "404_Page_not_found_(Expected_for_cloud5)"
        elif response_code == "000":
            curl_result = "Failed"
        update_line_starting("curl_"+short_name+":", "curl_"+short_name+": "+curl_result, setup_config_file)
    except Exception as e:
        pass

def get_session_type():
    command = "who am i | grep tty"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = process.communicate()
    output = output.decode().strip()
    if output:
        return "Connected via a console session"
    else:
        return "Connected via an SSH session"

def get_password(name=""):
    while True:
        password = input("Enter the '"+name+"' password: ")
        if re.match(r"^[^'\\]*$", password):
            return password
        else:
            print("Invalid password! Please avoid using apostrophe (') and backslash (\\) characters.")


def add_cert(cert_type, cert_path):
    while True:
        if check_file(cert_path) == "Y":
            certificate_type = determine_certificate_type(cert_path)
            if certificate_type == "Unknown":
                print("'"+cert_path+"' is an unsupported certificate type, please provide a DER or PEM encoded certificate")
                break
            else:                
                if certificate_type == "CA DER":
                    ca_cert_path = der_to_pem(cert_path)
                    ssl_cert_path = ""
                elif certificate_type == "CA PEM":
                    ca_cert_path = cert_path
                    ssl_cert_path = ""
                elif certificate_type == "SSL DER":
                    ssl_cert_path = der_to_pem(cert_path)
                    ca_cert_path = ""
                elif certificate_type == "SSL PEM":
                    ssl_cert_path = cert_path
                    ca_cert_path = ""
                
                directory_path = os.path.dirname(cert_path)
                filename_with_extension = os.path.basename(cert_path)
                filename_without_extension = os.path.splitext(filename_with_extension)[0]

                if "DMCA SSL" in cert_type:
                    if ssl_cert_path != "":
                        ssl_cert_password = get_password("DMCA SSL")
                        update_line_starting("ssl_cert_file_name:", "ssl_cert_file_name: "+filename_with_extension, setup_config_file)
                        update_line_starting("ssl_cert_file_location:", "ssl_cert_file_location: "+directory_path, setup_config_file)
                        update_line_starting("ssl_cert_file_pass:", "ssl_cert_file_pass: "+ssl_cert_password, setup_config_file)
                else:
                    if ca_cert_path != "":
                        new_path = directory_path+"/"+filename_without_extension+".crt"
                        os.rename(ca_cert_path, new_path)
                        update_line_starting("proxy_ca_cert:", "proxy_ca_cert: "+new_path, setup_config_file)
                    if ssl_cert_path != "":
                        update_line_starting("proxy_ssl_cert:", "proxy_ssl_cert: "+ssl_cert_path, setup_config_file)
                break
        else:
            print("No file found at '"+cert_path+"'")

def der_to_pem(der_path):
    # Read the DER certificate from the file
    with open(der_path, 'rb') as file:
        der_data = file.read()
    # Load the DER certificate
    cert = x509.load_der_x509_certificate(der_data, default_backend())
    # Convert the certificate to PEM encoding
    pem_data = cert.public_bytes(encoding=serialization.Encoding.PEM)
    # Write the PEM certificate to a file
    pem_path = der_path + '.pem'
    with open(pem_path, 'wb') as file:
        file.write(pem_data)
    return pem_path

def determine_certificate_type(cert_path):
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    try:# Check if CA or SSL PEM encoding
        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        if basic_constraints.value.ca:
            return "CA PEM"
        else:
            return "SSL PEM"
    except ValueError:
        pass
    try:# Check if CA or SSL DER encoding
        certificate = x509.load_der_x509_certificate(cert_data, default_backend())
        basic_constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        if basic_constraints.value.ca:
            return "CA DER"
        else:
            return "SSL DER"
    except ValueError:
        pass
    return "Unknown"

def update_defaults_file(key, file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    updated_lines = [line for line in lines if not line.startswith(key)]
    updated_lines.append(key+" '"+get_val(key).replace(" ", "")+"'"+'\n')
    with open(file_path, 'w') as file:
        file.writelines(updated_lines)

###################################################################################################
###                                     Main() starts here:                                     ###
###################################################################################################
stage = get_val("setup_stage:")

while True:
    #'''1
    while stage == "":        
        if get_val("setup_stage:") == "":
            startq = "You will need the following information to hand before proceeding:"
            startqo1 = "The IP address you want to assign to this machine\n"
            startqo2 = "The subnet mask for the above IP (in slash notation eg: /24)\n"
            startqo3 = "The default gateway IP for the above network\n"
            startqo4 = "At least one DNS server IP (can be internal and/or public)\n"
            startqo5 = "The hostname you wish to set for this machine\n    (otherwise the hostname will remain '"+current_hostname+"')\n"
            startqo6 = "NTP server IP/FQDN details if you have internal/preferred servers\n    (otherwise the default public servers will be used)\n"
            startqo7 = "Proxy details if required for internet access (IP/FQDN:Port, certificate(s))\n"
            startqo8 = "Your welcome email\n"

            question(startq, startqo1, startqo2, startqo3, startqo4, startqo5, startqo6, startqo7, startqo8)
        
        # Get and validate IP
        if get_val("ip_address:") == "":
            ASCII()
            print("Please provide the IP address you want this machine to use\n( subnetmask information will be collected later )\n")
            ip = valid_ip("IP address you wish to set for this VM")

        # Get and validata subnet mask
        if get_val("subnet_mask:") == "":
            ASCII()
            print("Please provide the subnet mask for the "+ip+"address")
            print("""( use slash notation, like /24 or /27 see below table )\n
255.255.255.252 = /30	255.255.255.248	= /29
255.255.255.240	= /28	255.255.255.224	= /27
255.255.255.192	= /26	255.255.255.128	= /25
255.255.255.0	= /24	255.255.254.0   = /23
255.255.252.0	= /22	255.255.248.0   = /21""")
            sn = valid_sn()

        # Get and validate default gateway IP
        if get_val("default_gateway:") == "":
            ASCII()
            print("Please provide the default Gateway IP for "+ip+"\n")
            gw = valid_ip("Default Gateway IP address")

        # Get Primary DNS IP
        if get_val("dns1:") == "":
            ASCII()
            print("Please provide the first DNS server IP you want this machine to use\nIt can be internal/private and/or external/public\n")
            dns1 = valid_ip("DNS 1 IP address")
            ASCII()
            print("DNS 1 set to: "+dns1+"\n\ndo you want to add a second DNS server?")
            if yn() == "Y":
                # Get Secondary DNS IP
                ASCII()
                print("Please provide the second DNS server IP you want this machine to use\nIt can be internal/private and/or external/public\n")
                dns2 = valid_ip("DNS 2 IP address")
                ASCII()
                print("DNS 2 set to: "+dns2+"\n\ndo you want to add a third DNS server?")
                if yn() == "Y":        
                    # Get Tertiary DNS IP
                    ASCII()
                    print("Please provide the third DNS server IP you want this machine to use\nIt can be internal/private and/or external/public\n")
                    dns3 = valid_ip("DNS 3 IP address")
                else:
                    dns3 = ""
            else:
                dns2 = ""
                dns3 = ""

        # Get new hostname
        if get_val("hostname:") == "":
            ASCII()
            current_hostname = socket.gethostname()
            print("Do you want to change the hostname of this machine?\nit is currently set to: "+current_hostname)
            if yn() == "Y":
                new_hostname = valid_hostname()
            else:
                new_hostname = current_hostname

        # NTP config
        if get_val("ntp_address:") == "":
            ASCII()
            print("This machine is currently configured to use a pool of NTP servers from ntp.org\nDo you want to provide your own NTP server/pool details?")
            if yn() == "Y":
                ASCII()
                ntpq = "What information will you be providing?"
                ntpqo1 = "An NTP pool Virtul-IP address"
                ntpqo2 = "A single NTP server IP address"
                ntpqo3 = "An NTP pool hostname/FQDN"
                ntpqo4 = "A single NTP server hostname/FQDN"
                ntpa = question(ntpq, ntpqo1, ntpqo2, ntpqo3, ntpqo4)

                if ntpa == 1:
                    new_ntp = valid_ip("NTP pool Virtual-IP address")
                elif ntpa == 2:
                    new_ntp = valid_ip("NTP server IP address")
                elif ntpa == 3:
                    print("Please enter the NTP pool hostname/FQDN")
                    new_ntp = valid_hostname()
                elif ntpa == 4:
                    print("Please enter the NTP server hostname/FQDN")
                    new_ntp = valid_hostname()
            else:ntpa = 0

        ##################################################################################
        # confirm with user that all details are correct
        ASCII()
        print(f"""
IP and subnetmask for this machine:                   {ip}/{sn}
The default gateway for this machine:                 {gw}
The DNS server(s) this machine will use:       DNS 1: {dns1}""")
        if dns2 != "":
            print(f"                                               DNS 2: {dns2}")
        if dns3 != "":
            print(f"                                               DNS 3: {dns3}")
            print(f"The hostname for this machine will be:                {new_hostname}")
        if ntpa == 1 or ntpa == 3:
            ntpstring="pool "+new_ntp+" iburst"
            print(f"You have chosen to use the NTP pool:                  {new_ntp}")
        elif ntpa == 2 or ntpa == 4:
            ntpstring="server "+new_ntp+" iburst"
            print(f"You have chosen this single NTP server:               {new_ntp}")
        else:
            print(f"This machine will use the default NPT pool:           2.debian.pool.ntp.org")

        print("\n\nAre all of the details above correct?\n( N will restart this setup script )\n")

        if yn() == "Y":
            stage = "network_collect"
            update_line_starting("setup_stage:","setup_stage: network_collect", setup_config_file)
            break

    ##################################################################################
    # Apply settings
    while stage == "network_collect":
    ### Networking (IP, Subnet, Gateway, default network adapter)
        int_file = "/etc/network/interfaces"
        backup_original(int_file)
        dadapter = subprocess.check_output("ip -br a | grep en | awk '$1 !~ \"lo|vir|wl\" { print $1}'", shell=True)
        dadapter = dadapter.decode("utf-8").strip()
        if dadapter != "ens192":
            update_word("ens192", dadapter, int_file)
        update_line_starting("        gateway ", "        gateway "+gw, int_file)
        update_line_starting("        address ", "        address "+ip+"/"+sn, int_file)
        update_line_starting("ip_address:", "ip_address: "+ip, setup_config_file)
        update_line_starting("subnet_mask:", "subnet_mask: "+sn, setup_config_file)
        update_line_starting("default_gateway:", "default_gateway: "+gw, setup_config_file)
        print("IP settings applied\n")
    ### DNS
        dns_file = "/etc/resolv.conf"
        backup_original(dns_file)
        with open(dns_file, 'w') as file:
            # Use truncate() to remove all data from the file
            file.truncate()
        # Open the file in append mode to add new lines
        with open(dns_file, 'a') as file:
            # Write new lines using write()
            file.write("nameserver "+dns1)
            update_line_starting("dns1:", "dns1: "+dns1, setup_config_file)
            if dns2 != "":
                file.write("\nnameserver "+dns2)
                update_line_starting("dns2:", "dns2: "+dns2, setup_config_file)
            if dns3 != "":
                file.write("\nnameserver "+dns3)
                update_line_starting("dns3:", "dns3: "+dns3, setup_config_file)
        print("DNS settings applied\n")
    ### Hostname
        if new_hostname != current_hostname:
            hostname_file = "/etc/hostname"
            backup_original(hostname_file)
            os.system(f"hostnamectl set-hostname {new_hostname}")
            update_line_starting("hostname:", "hostname: "+new_hostname, setup_config_file)
            print("Hostname settings applied\n")
        else:
            update_line_starting("hostname:", "hostname: "+current_hostname, setup_config_file)
            print("The hostname is remaining set to "+current_hostname+"\n")
    ### NTP
        if ntpa != 0:
            ntp_file = "/etc/chrony/chrony"
            backup_original(ntp_file)
            default_ntp = "pool 2.debian.pool.ntp.org iburst"            
            update_line_containing(default_ntp, ntpstring, ntp_file)
            update_line_starting("ntp_address:", "ntp_address: "+new_ntp, setup_config_file)
            if ntpa ==1 or ntpa ==3:
                update_line_starting("ntp_pool_or_server:", "ntp_pool_or_server: pool", setup_config_file)
            else:
                update_line_starting("ntp_pool_or_server:", "ntp_pool_or_server: server", setup_config_file)
            print("NTP settings applied\n")
        else:
            update_line_starting("ntp_address:", "ntp_address: 2.debian.pool.ntp.org", setup_config_file)
            update_line_starting("ntp_pool_or_server:", "ntp_pool_or_server: pool", setup_config_file)            
            print("NTP settings default\n")
    ### Restart networking service
        print("Restarting networking services\n")
        subprocess.run(["systemctl", "restart", "networking.service"])
        print("Done applying the network changes\n")

####### Running network tests
    ### LAN
        ASCII()
        print("Done applying the network changes, starting tests...\n\nIs PING/ICMP disabled/blocked on this network?")
        if yn() == "N":
            if ping(gw, "ping_lan:") == "restart_setup":
                stage = ""
                break
            print("Running network tests, 1 of 13 complete  |#            |\r", end="")
            ping("8.8.8.8", "ping_wan:")
            print("Running network tests, 2 of 13 complete  |##           |\r", end="")
            ping("google.com", "ping_fqdn:")
            print("Running network tests, 3 of 13 complete  |###          |\r", end="")
        else:
            print("Skipping PING tests")
        
    ### WAN
        portal = "https://portal.vnocsymphony.com"
        portal5 = "https://portal5.avisplsymphony.com"
        cloud = "https://cloud.vnocsymphony.com"
        cloud5 = "https://cloud5.avisplsymphony.com"
        registry = "https://registry.vnocsymphony.com"

        check_server(portal)
        print("Running network tests, 5 of 13 complete  |#####        |\r", end="")
        check_server(portal5)
        print("Running network tests, 7 of 13 complete  |#######      |\r", end="")
        check_server(cloud)
        print("Running network tests, 9 of 13 complete  |#########    |\r", end="")
        check_server(cloud5)
        print("Running network tests, 11 of 13 complete |###########  |\r", end="")
        check_server(registry)
        print("Running network tests, 13 of 13 complete |#############|")

        read_ping_lan = get_val("ping_lan:")
        read_ping_wan = get_val("ping_wan:")
        read_ping_fqdn = get_val("ping_fqdn:")
        read_wget_portal = get_val("wget_portal:")
        read_wget_portal5 = get_val("wget_portal5:")
        read_wget_cloud = get_val("wget_cloud:")
        read_wget_cloud5 = get_val("wget_cloud5:")
        read_wget_registry = get_val("wget_registry:")
        read_curl_portal = get_val("curl_portal:")
        read_curl_portal5 = get_val("curl_portal5:")
        read_curl_cloud = get_val("curl_cloud:")
        read_curl_cloud5 = get_val("curl_cloud5:")
        read_curl_registry = get_val("curl_registry:")

        print("\n##########  PINGs ##########\n")
        print("PING LAN IP:   "+read_ping_lan)
        print("PING WAN IP:   "+read_ping_wan)
        print("PING WAN FQDN: "+read_ping_fqdn)
        print("\n##########  WGETs ##########\n")
        print("WGET portal:   "+read_wget_portal)
        print("WGET portal5:  "+read_wget_portal5)
        print("WGET cloud:    "+read_wget_cloud)
        print("WGET cloud5:   "+read_wget_cloud5)
        print("WGET registry: "+read_wget_registry)
        print("\n##########  CURLs ##########\n")
        print("CURL portal:   "+read_curl_portal)
        print("CURL portal5:  "+read_curl_portal5)
        print("CURL cloud:    "+read_curl_cloud)
        print("CURL cloud5:   "+read_curl_cloud5)
        print("CURL registry: "+read_curl_registry)

        enter_to_cont()
        
        ASCII()
        update_line_starting("setup_stage:","setup_stage: network_applied", setup_config_file)        
        if question("The network configuration portion setup is complete\n\nWe recommend that you now disconnect from this session\nand then reconnect via SSH to finish the setup process\nas that will allow you to paste in details from your welcome email\n\nDo you want to disconnect from this session now?","Yes (Reconnect via SSH (symphony@"+ip+" and the password starting '5ym'))","No  (Manually type in the details from the welcome email in this session)") == 1:
            os.system('pkill -KILL -u symphony')
        stage = "network_applied"
    stage = get_val("setup_stage:")
    while stage == "network_applied":
        ASCII()
        print(get_session_type()+", resuming setup...")
        enter_to_cont()
        ASCII()        
    ### Check if using DMCA
        if get_val("dmca_config_check:") == "":
            print("Do you intend to use DMCA? (for monitoring Windows based devices)")
            if yn() == "Y":
                update_line_starting("dmca_config_check:", "dmca_config_check: yes", setup_config_file)
            else:
                update_line_starting("dmca_config_check:", "dmca_config_check: no", setup_config_file)
                update_line_starting("ssl_cert_file_name:", "ssl_cert_file_name: N/A", setup_config_file)
                update_line_starting("ssl_cert_file_pass:", "ssl_cert_file_pass: N/A", setup_config_file)
                update_line_starting("ssl_cert_file_location:", "ssl_cert_file_location: N/A", setup_config_file)

    ### Check if using a proxy
        if get_val("proxy_type:") == "":
            ASCII()
            print("Do you need this server to be configured to use a web proxy for HTTP(S) communication?")
            if yn() == "N":
                update_line_starting("proxy_type:","proxy_type: N/A", setup_config_file)
                update_line_starting("proxy_cert_req:","proxy_cert_req: N/A", setup_config_file)
                update_line_starting("proxy_address:","proxy_address: N/A", setup_config_file)
                update_line_starting("proxy_port:","proxy_port: N/A", setup_config_file)
                update_line_starting("proxy_ca_cert:","proxy_ca_cert: N/A", setup_config_file)
                update_line_starting("proxy_int_cert:","proxy_int_cert: N/A", setup_config_file)
                update_line_starting("proxy_ssl_cert:","proxy_ssl_cert: N/A", setup_config_file)
            else:
                ASCII()
                proxyq = "Select the option which best describes your proxy"
                proxyqo1 = "A regular proxy (has a http:// prefix) and DOES NOT decrypt external certificates\n  (Commonly referred to as a transparent proxy)\n"
                proxyqo2 = "A regular proxy (has a http:// prefix) and DOES decrypt external certificates and then re-encrypt the traffic with its own certificate\n  (Commonly referred to as a non-transparent proxy)\n"
                proxyqo3 = "A secure proxy (has a https:// prefix) and DOES NOT decrypt external certificates and then re-encrypt the traffic with its own certificate\n  (Commonly referred to as a secure transparent proxy (a TLS connection is always established between the client and the proxy))\n"
                proxyqo4 = "A secure proxy (has a https:// prefix) and DOES decrypt external certificates and then re-encrypt the traffic with its own certificate\n  (Commonly referred to as a secure non-transparent proxy (a TLS connection is always established between the client and the proxy))\n"
                proxyqo5 = "Cancel / Skip proxy settings"
                proxyqa = question(proxyq, proxyqo1, proxyqo2, proxyqo3, proxyqo4, proxyqo5)

                if proxyqa == 1:
                    print("\nThis should work, details will be collected in the next step")
                    update_line_starting("proxy_type:","proxy_type: http:// and NO fixup", setup_config_file)
                    # should not need CA cert
                elif proxyqa == 2:
                    print("\nThis should work, however if the proxy certificate is self-signed (not publicly trusted) some functionality may not work")
                    print("specifically, the ability to remotely restart and upgrade the CPX, but the main funcion of collecting and sending monitoring data should still work")
                    print("details will be collected in the next step")
                    # will need CA cert
                    update_line_starting("proxy_type:","proxy_type: http:// with fixup", setup_config_file)
                elif proxyqa == 3:
                    print("\nNot currently supported")
                    # need to test with the proxy Dan said we had
                    # will need SSL cert
                    update_line_starting("proxy_type:","proxy_type: https:// and NO fixup", setup_config_file)
                elif proxyqa == 4:
                    print("\nNot currently supported")                    
                    # need to test with the proxy Dan said we had
                    # will need SSL and CA cert
                    update_line_starting("proxy_type:","proxy_type: https:// with fixup", setup_config_file)

                enter_to_cont()

                #record if proxy cert(s) required)
                #if proxyqa != 1 and proxyqa != 5: # for if/when options 3 and 4 work
                if proxyqa == 2:
                    update_line_starting("proxy_cert_req:", "proxy_cert_req: yes", setup_config_file)

                #if proxyqa != 5 or proxyqa != 1: # for if/when options 3 and 4 work
                if proxyqa == 1 or proxyqa == 2:
                    while True:
                        ASCII()
                        test_proxy_address = input("Enter the full proxy address and port number\n( For example http://proxy.acmetntco.com:8080\n           or https://101.102.103.104:8443 )\n>")
                        valid, address_type, address, port = validate_proxy_address(test_proxy_address)
                        if valid:                            
                            update_line_starting("proxy_port:", "proxy_port: "+port, setup_config_file)
                            update_line_starting("proxy_address:", "proxy_address: "+address, setup_config_file)
                            break
    ### Install required certs    
        ip = get_val("ip_address:")
        proxy_type = get_val("proxy_type:")
        if get_val("dmca_config_check:") == "yes" or get_val("proxy_cert_req:") == "yes":
            
            req_cert_list = []
            ASCII()
            print("The following certificates are required:\n")
            if get_val("dmca_config_check:") == "yes" and get_val("ssl_cert_file_name:") == "":
                print("-- DMCA SSL certificate\n")
                req_cert_list.append("DMCA SSL certificate")
            if proxy_type == "http:// with fixup" and get_val("proxy_ca_cert:") == "":
                print("-- Proxy CA certificate\n")
                req_cert_list.append("Proxy CA certificate")
            if proxy_type == "https:// and NO fixup" and get_val("proxy_ssl_cert:") == "":
                print("-- Proxy SSL certificate\n")
                req_cert_list.append("Proxy SSL certificate")
            if proxy_type == "https:// with fixup" and get_val("proxy_ca_cert:") == "" and get_val("proxy_ssl_cert:") == "":
                print("-- Proxy CA certificate")
                print("-- Proxy SSL certificate\n")
                req_cert_list.append("Proxy CA certificate")
                req_cert_list.append("Proxy SSL certificate")
            if len(req_cert_list) > 0:
                print("Do you have the above certificates uploaded to this server already?")
                if yn() == "N":
                    print("\nSetup will now pause here to allow you to upload them to this server\nAlternatively you can quit this setup now to upload them\n(The setup will resume from here next time you login)\n")
                    print("Do you have the certificates uploaded now?\n('yes' to provide certificate paths, 'no' to quit)")
                    if yn() == "N":
                        quit()
                while len(req_cert_list) > 0:                
                    cert_type = req_cert_list.pop(0)
                    cert_to_add = certificate(cert_type)
                    add_cert(cert_type, cert_to_add)
####### Symphony information collection
        ASCII()
        print("Collecting Symphony specific settings now\n( you will need your welcome email )")
        enter_to_cont()
        if get_val("account_name:") == "":
            while True:
                ASCII()
                print("Please enter your desired account name\n\nThis can be anything, it will only be used to name folders and services on this server\nAs such it should only consist of a-z, A-Z, - (hyphen) and _ (underscore)\n")
                an = input("Enter the desired Account Name: ")
                if re.match(r'^[a-zA-Z_-]+$', an):  # check for only valid characters
                    update_line_starting("account_name:", "account_name: "+an, setup_config_file)
                    break
                else:
                    print("\nThe 'Account Name' entered is not valid\nCheck that it only consists of the allowed characters")
                    enter_to_cont()

        if get_val("account_id:") == "":
            while True:
                ASCII()
                print("Please enter the 'Account ID' from the welcome email\nIt consists of a-z, 0-9, and - (hyphen)\n")
                aid = input("Enter the Account ID (including the hyphens): ")
                if re.match(r'^[a-z0-9-]+$', aid) and len(aid) == 36:
                    update_line_starting("account_id:", "account_id: "+aid, setup_config_file)
                    break
                else:
                    print("\nThe 'Account ID' entered is not valid\nCheck that it only consists of the allowed characters (including the hyphens)")
                    enter_to_cont()

        if get_val("account_portal:") == "":
            while True:
                ASCII()
                print("Please enter the 'Symphony Portal' from the welcome email\nIt consists of 3 or 4 letters)\n")
                portal = input("Enter the Symphony Portal: ")
                if portal.lower().startswith("p"):
                    env = "prod"
                elif portal.lower().startswith("e"):
                    env = "emea"
                elif portal.lower().startswith("i") or portal.lower().startswith("s"):
                    env = "int"
                elif portal.lower().startswith("d"):
                    env = "dev"
                else:
                    print("\nUnknown/invalid Portal environment provided")
                    enter_to_cont()
                    env = ""
                if env != "":
                    update_line_starting("account_portal:", "account_portal: "+env, setup_config_file)
                    break

        if get_val("cpx_serviceUserEmail:") == "":
            while True:
                ASCII()
                print("Please enter the 'Cloud Connector Username' from the welcome email\n")
                ccu = input("Enter the Cloud Connector Username: ")
                if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ccu):
                    update_line_starting("cpx_serviceUserEmail:", "cpx_serviceUserEmail: "+ccu, setup_config_file)
                    break
                else:
                    print("\nInvalid 'Cloud Connector Username' entered\n(It should be in the format of an email address)")
                    enter_to_cont()

        if get_val("cpx_serviceUserPassword:") == "":
            while True:
                ASCII()
                print("Please enter the 'Cloud Connector Password' from the welcome email\n")                    
                ccp = get_password("Cloud Connector Password")
                if len(ccp) > 0:
                    update_line_starting("cpx_serviceUserPassword:", "cpx_serviceUserPassword: "+ccp, setup_config_file)
                    break
#########################################################################################################
########### Info collection done
    ### Now add colledted data to the Ansible variable file (or update them if they already exist)            
        defaults_file = "/symphony/symphony-cpx-ansible-role/defaults/main.yml"
        defaults_vars = ["account_name:", "account_id:", "account_portal:", "cpx_serviceUserEmail:", "cpx_serviceUserPassword:", "dmca_config_check:", "ssl_cert_file_name:", "ssl_cert_file_location:", "ssl_cert_file_pass:"]
        for i in defaults_vars:
            update_defaults_file(i, defaults_file)

    ### generate the new initial yaml file (excluding the questions), which replaces the start_here.yml file
        playbook = '''---
- hosts: localhost
#  become: yes
#
# Questions and answer section omitted, as that`s already done in the script
#
###
#
# START PLAYBOOK AFTER QUESTIONS ARE ANSWERED AND SAVED
#
####
  tasks:
    - name: Include OS-specific variables.
      include_vars: "{{ playbook_dir }}/defaults/main.yml"
    # check if playbook has been run and fail if it has
    # this prevents changing cpx config settings and systems that have already been
    - name: Check if playbook was run before
      stat:
        path: "{{ symphony_prerun_dir }}/{{ pre_run_check_file }}"
      register: prerun_check

    - name: Configuration Pre Check
      fail:
        msg: "This playbook has run on this system previously"
      when: prerun_check.stat.exists

    - name: Configuration Pre Check
      fail:
        msg: "This playbook has run on this system previously"
      when: prerun_check.stat.exists

    - import_tasks: "tasks/main.yml"
'''
    ### it is given the new file name of new_start.yml (so the original method remains in place)
        new_playbook="/symphony/symphony-cpx-ansible-role/new_start.yml"
        if os.path.exists(new_playbook):
            os.remove(new_playbook)
        subprocess.run(["sudo", "-u", "symphony", "touch", new_playbook])
        with open(new_playbook, 'a') as file:
            file.write(playbook)

####### Run the newly created playbook
        command = 'sudo -u symphony ansible-playbook '+new_playbook
        subprocess.run(command, shell=True)

########After playbook tasks
        ASCII()
        print("\nPerforming post-install configuration changes...\n\nUpdating crontab settings...\n")
    ### Update CronTab
        cron_bash = '''
crontab -l | sort -u | crontab -
if [[ $(crontab -l | head -n 1) != 'MAILTO=""' ]]; then
    (echo 'MAILTO=""'; crontab -l) | crontab -
fi
'''
        subprocess.run(['bash', '-c', cron_bash])

    ### make the cron logs folder
        folder_path = '/symphony/cpx/logs'
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            print("Cron settings applied and logs folder created\n")

    ### Get and display external IP
        print("Getting external IP address...")
        external_ip = ""
        url_1 = "https://ifconfig.me"
        url_2 = "https://ipinfo.io/ip"
        url_3 = "https://api.ipify.org"
        response = requests.get(url_1)
        if response.status_code == 200:
            external_ip = response.text.strip()
        else:
            print("Unable to get external IP from 'ifconfig.me'... trying ipinfo.io/ip...")
            response = requests.get(url_2)
            if response.status_code == 200:
                external_ip = response.text.strip()
            else:
                print("Unable to get external IP from 'ipinfo.io/ip'... trying api.ipify.org...")
                response = requests.get(url_3)
                if response.status_code == 200:
                    external_ip = response.text.strip()
                else:
                    print("Unable to get external IP from 'api.ipify.org'... trying the last resort...")
                    command = "dig @resolver1.opendns.com myip.opendns.com +short"
                    output = ""
                    output = subprocess.check_output(command, shell=True).decode().strip()
                    if output != "":
                        external_ip = response.text.strip()
                    else:
                        print("Unable to get external IP.")
        if external_ip:
            print("The external IP of this server is:", external_ip)
        
    ### Finished
        update_line_starting("setup_stage:","complete")
        print("Setup has finished, monitor the CPX latency graph in symphony,\nActivity should be visible in Symphony Portal within the next few minutes")
        enter_to_cont()
    