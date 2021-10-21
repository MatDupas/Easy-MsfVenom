![Logo](https://user-images.githubusercontent.com/26366683/137634034-dae33eda-1b59-4ed8-a9ec-597c8a5200e5.png)

**Goal :**
**Search, generate & deliver MSFVENOM payloads in an quick and easy way. Be as simple as possible BUT with all payloads.**

* Ever lost time searching the right MSFpayload ? Use the fast filter for instantaneous results !
* Tired of inputing your IP, and defaults settings ? Let Easy-MsfVenom do it for you or ask for info.
* Automatically launch Meterpreter listeners with the right payload or a netcat listener.
* Want only stageless  payloads (`-s`) ? Only Meterpreter ones (`-m`)?  
* Want to explore other options ? Want a ruby / python/ perl payload? use `-k or --keyword` argument.

![Easy-msfvenom1](https://user-images.githubusercontent.com/26366683/138068924-460bca34-975f-48ab-a1e0-e6a7873d3aa6.png)

![Easy-msfvenom2](https://user-images.githubusercontent.com/26366683/138066717-8ce90064-5bb5-47c7-aaf2-e38e049b2c1c.png)


#  Features 
* Fast search through all Venom payloads.
* Filter by Meterpreter / Bind / Reverse / architecture ... 
* Integrated easy delivery:
	- Http server for Bind shells.
* Integrated listener for Reverse shells:
	- launch of Msfconsole handler for Metasploit payloads.
	- Launch of netcat listener for other payloads. 

# Usage

**Note: By default, if omitted, we'll get `x86  bind staged payloads`**

- **Interactive Mode:**
  - Win shells /payloads :   ` ./Easy-MsfVenom.py  -t win  `
    
  - Linux shells /payloads : ` ./Easy-MsfVenom.py  -t lin  `
  
  - Web shells (PHP,ASP, Java) :` ./Easy-MsfVenom.py  -t web `

- **Some classics :**
  - Meterpreter Windows(x86) Bind_TCP payloads:   ` ./Easy-MsfVenom.py  -t win -m `
  
  - Meterpreter Windows(x86) Reverse TCP payloads: `./Easy-MsfVenom.py  -t win -m -r `
   
- **Custom search :**
   - Python Bind_TCP payloads
    ```bash 
    ./Easy-MsfVenom.py  -k python
    ```
 
- **Full control :**
  - Meterpreter Win(x64) Stageless Reverse_TCP payloads: 
    ```bash
    ./Easy-MsfVenom.py  -t win -a x64 -m -s -r -p 4444
    ```


# TO-DO:
- [ ] Add encoders with fast filters
- [ ] Add batch payloads
- [ ] Add other formats (.ps1, .py)



# Requirement
* Python 3.x
* Metasploit-framework

# Installation


```bash   
  git clone https://github.com/MatDupas/Easy-MsfVenom
  cd Easy-MsfVenom; chmod +x ./Easy-MsfVenom.py; ./Easy-MsfVenom.py --upgrade
```

# Upgrade
To keep Easy-MsfVenom synchronized with all MsfVenom payloads, just do:
```bash   
  ./Easy-MsfVenom.py --upgrade
```

Note: it is useful to also keep metasploit-framework updated
`sudo apt update; sudo apt install metasploit-framework`
(it is better to make  backup before upgrading, just in case...)

# Trick

To clean up your folder from all your payloads, just do :
```bash
rm _*
```
# FAQ

**How Easy-MsfVenom differ from MSFPC ?**
[MSFPC](https://github.com/g0tmi1k/msfpc) from g0tmi1k  is a BASH wrapper to generate multiple types of payloads, based on users choice.
My global view is that MSFPC is  a 4WD that can work on any *NIX machine thanks to bash and works great when user knows what he needs.
If user wants to explore other options or is not a seasoned practitioner, he can use Easy-MsfVenom to get help and try new payloads.

**What are the main goals of this tool  ?**
- My first goal was to add some keyword searching so anybody can explore not just the classics payloads but also one of the other great 600 payloads
   - -> for ex ruby payloads : `Easy-MsfVenom.py -k ruby` 
        -> will instantaneously  display the 12 avail. payloads without waiting 50 seconds like on my VM (use of a caching mechanism to speed things up)
    
- My second goal was to be as 'lazy' and frugal for typing :  the tool just need a keyword arg to start and everything else will be guessed or asked.


# Legal / Ethics
>` TL;DR: Don't be evil, stay on the right side `

This software is for educational and Pentesting /Red Teaming purposes only.
As a reminder, Attacking targets without prior mutual consent is illegal. It is the end user’s responsibility to obey all applicable local, state and federal laws. 
The author assume no liability and no responsability for any misuse or damage caused by this software.

Easy-MsfVenom © 2021 by Mathieu Dupas is licensed under [CC BY-NC 4.0](http://creativecommons.org/licenses/by-nc/4.0/?ref=chooser-v1)


