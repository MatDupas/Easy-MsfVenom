![Logo](https://user-images.githubusercontent.com/26366683/137634034-dae33eda-1b59-4ed8-a9ec-597c8a5200e5.png)

**Goal :**
**Search, generate & deliver MSFVENOM payloads in an quick and easy way. Be as simple as possible BUT with all payloads.**

* Ever lost time searching the right MSFpayload ? Use the fast filter.
* Tired of inputing your IP, and defaults settings ? Let Easy-MsfVenom do it for you or ask for info.
* Want only stageless  payloads (`-s`) ? Only Meterpreter ones (`-m`)?  
* Want more complex options ? Want a hidden_tcp ? use `-k or --keyword` argument.

![Easy-MsfVenom-screenshot](https://user-images.githubusercontent.com/26366683/137700327-d5e44686-6be7-4214-b8d9-de4edd67b93a.png)


#  Features 
* fast search through all Venom payloads.
* filter by Meterpreter / Bind / Reverse / architecture ... 
* integrated easy delivery:
	- Http server for Bind shells.
* Integrated listener for Reverse shells:
	- launch of Msfconsole handler for Metasploit payloads.
	- Launch of netcat listener for other payloads. 

# Usage

**Note: By default, if omitted, we'll get `x86  bind staged payloads`**

- **Interactive Mode:**
  - Win shells /payloads : 
    ```bash
    ./Easy-MsfVenom.py  -t win
    ```
    
  - Linux shells /payloads :
    ```bash 
    ./Easy-MsfVenom.py  -t lin
    ```
  - Web shells /payloads (PHP,ASP, Java) :
    ```bash 
    ./Easy-MsfVenom.py  -t web
    ```

- **Some classics :**
  - Meterpreter Windows(x86) Bind_TCP payloads:
    ```bash 
    ./Easy-MsfVenom.py  -t win -m
    ```
  - Meterpreter Windows(x86) Reverse TCP payloads:
    ```bash 
    ./Easy-MsfVenom.py  -t win -m -r
    ```


- **Custom search :**
   - Hidden Meterpreter Windows(x86) Bind_TCP payloads
    ```bash 
    ./Easy-MsfVenom.py  -t win -m -k hidden
    ```
 
- **Full control :**
  - Meterpreter Win(x64) Stageless Reverse_TCP payloads: 
    ```bash
    ./Easy-MsfVenom.py  -t win -a x64 -m -s -r -p 4444
    ```


# TO-DO:
- [ ] Add encoders with fast filters
- [ ] Add batch payloads
- [ ] Add other formats
- [ ] Improve payload name : they presently reflect the original params, not the brodened one.

 


# Requirement
* Python 3.x
* Metasploit-framework

# Installation


```bash   
  git clone https://github.com/MatDupas/Easy-MsfVenom
  cd Easy-MsfVenom; ./Easy-MsfVenom.py --upgrade
```

# Upgrade
To keep Easy-MsfVenom synchronized with all MsfVenom payloads, just do:
```bash   
  ./Easy-MsfVenom.py --upgrade
```

Note: it is useful to also keep metasploit-framework updated
sudo apt update; sudo apt install metasploit-framework
(it is better to make  backup before upgrading, just in case...)

# Trick

To clean up your folder from all your paylaods, just do :
```bash
rm _*
```


# Legal / Ethics
>` TL;DR: Don't be evil, stay on the right side `

This software is for educational and Pentesting /red Teaming purposes only.
As a reminder, Attacking targets without prior mutual consent is illegal. It is the end user’s responsibility to obey all applicable local, state and federal laws. 
The author assume no liability and no responsability for any misuse or damage caused by this software.

Easy-MsfVenom © 2021 by Mathieu Dupas is licensed under [CC BY-NC 4.0](http://creativecommons.org/licenses/by-nc/4.0/?ref=chooser-v1)


