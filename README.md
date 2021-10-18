![Logo](https://user-images.githubusercontent.com/26366683/137634034-dae33eda-1b59-4ed8-a9ec-597c8a5200e5.png)

Easy-MsfVenom 

**Goal**: search, generate & deliver payloads in an quick and easy way
Be as simple as possible BUT with all msfvenom payloads.

* Ever lost time Searching the right MSFpayload ? Use the fast filter
* Tired of inputing your IP, and defaults settings ? let Easy-MsfVenom do it or ask for it !
* Want only stageless  payloads (`-s`) ? Only Meterpreter ones (`-m`)?  
* want more complex options ? want a hidden_tcp ? use `-k or --keyword` argument !


![Easy-MsfVenom-screenshot](https://user-images.githubusercontent.com/26366683/137633631-a0c40732-1a18-4409-a599-1bc0b5af75e5.png)




#  Features 
* fast search through all Venom payloads
* filter by Meterpreter / Bind / Reverse / architecture ... 
* integrated easy delivery
	- Http server for Bind shells
* Integrated listener for Reverse shells
	- launch of Msfconsole handler for Metasploit payloads
	- Launch of netcat listener for other payloads 



# Usage

**Note: By default, if omitted, we'll get `x86  bind staged payloads`**

- Some classics :
  - Meterpreter Windows(x86) Reverse TCP payloads:
    ```bash 
    ./Easy-MsfVenom.py  -t win -m -r
    ```
  - Meterpreter Windows(x86) Bind_TCP payloads:
    ```bash 
    ./Easy-MsfVenom.py  -t win -m
    ```

- Want Minimum arguments and get interactive completion :
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

- Want more complex ones like **"hidden ports"** :
  - Hidden Meterpreter Windows(x86) Bind_TCP payloads
    ```bash 
  ./Easy-MsfVenom.py  -t win -m -k hidden
    ```
  - Android payloads (x86) Bind_TCP payloads
    ```bash 
  ./Easy-MsfVenom.py  -t win -m -k hidden
    ```
  - Mac OS reverse staged paylaods:
    ```bash   
  ./Easy-MsfVenom.py -k osx
    ```




# TO-DO:
- [ ] Add encoders with fast filters
- [ ] Add batch payloads

 


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

# Legal / Ethics
>` TL;DR: Don't be evil, stay on the right side `

This software is for educational and Pentesting /red Teaming purposes only.
As a reminder, Attacking targets without prior mutual consent is illegal. It is the end user’s responsibility to obey all applicable local, state and federal laws. 
The author assume no liability and no responsability for any misuse or damage caused by this software.

Easy-MsfVenom © 2021 by Mathieu Dupas is licensed under [CC BY-NC 4.0](http://creativecommons.org/licenses/by-nc/4.0/?ref=chooser-v1)


