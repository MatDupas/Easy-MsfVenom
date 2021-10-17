

   ____                 __  ____________   __                  
  / __/__ ______ ______/  |/  / __/ __/ | / /__ ___  ___  __ _ 
 / _// _ `(_-< // /___/ /|_/ /\ \/ _/ | |/ / -_) _ \/ _ \/  ' \
/___/\_,_/___|_, /   /_/  /_/___/_/   |___/\__/_//_/\___/_/_/_/
            /___/                                              
  
Easy-MsfVenom - V1



Goal: search, generate & deliver payloads in an quick and easy way
Be as simple as possible BUT with all msfvenom payloads.

* ever lost some time by searching the right payload ? Use the fast filter
* Tired of inputing your IP, and defaults settings ? let Easy-MsfVenom do it for you
* Want only staged  payloads ? only Meterpreter ones ?  ask for it
* want more complex options ? want a hidden_tcp ? you find them

#  Features 
* fast search through all Venom payloads
* filter by Meterpreter / Bind / Reverse / architecture ... 
* integrated easy delivery
	- Http server for Bind shells
* Integrated listener for Reverse shells
	- launch of Msfconsole handler for Metasploit payloads
	- Launch of netcat listener for other payloads 



# Usage

# TO-DO:
[] Add encoders with fast filters and batch payloads encoding
[
 


# Requirement
* Python 3.x
* Metasploit-framework

# Installation

> git clone
> cd Easy-msfVenom
> install.sh

# Upgrade
To keep Easy-MsfVenom synchronized with all MsfVenom payloads, just do:

> ./easy-MsfVenom --upgrade

Note: it is useful to also keep metasploit-framework updated
sudo apt update; sudo apt install metasploit-framework
(it is better to make  backup before upgrading, just in case...)

# Legal / Ethics
TL;DR: Don't be evil, stay on the right side

This software is for educational and Pentesting /red Teaming purposes only.
As a reminder, Attacking targets without prior mutual consent is illegal. It is the end user’s responsibility to obey all applicable local, state and federal laws. 
The author assume no liability and no responsability for any misuse or damage caused by this software.



