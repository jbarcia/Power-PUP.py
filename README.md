# Powershell Universal Programmer
## (Power-PUP.py)
Powershell Universal Programmer (Power-PUP.py) is a Windows Python script to compile Windows System.Management.Automation for a powershell alternative.


### USAGE:
```sh
Powershell Universal Programmer

Usage: Power-PUP.py -a target_architecture
-a | --arch                - architecture of the target host
-o | --output              - executable output name
```

### Examples: 
* Power-PUP.py -a x86
* Power-PUP.py -a x64 -o psx64.exe

### Info:
```sh
#---------------------------------------------------------------#
#!/bin/python2                                                  #
#-Metadata------------------------------------------------------#
#  Filename: Power-PUP.py                                       #
#  Version: 1.0                                                 #
#  Release: 2016-07-26                                          #
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
#  -a | --arch                - architecture of the target host #
#  -o | --output              - executable output name          #
#                                                               #
# Examples:                                                     #
# Power-PUP.py -a x86                                           #
# Power-PUP.py -a x64 -o psx64.exe                              #
#                                                               #
#-Future Additions----------------------------------------------#
#  - Detect .Net Version                                        #
#       HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\                  #
#       NET Framework Setup\NDP\v4\Full\InstallPath             #
#  - Create options for common payloads                         #
#       (mimi/invoke-shell/ps1)                                 #
#  - A/V XOR bypass                                             #
#  - Input a file containing ps commands (single or multiple)   #
#                                                               #
#---------------------------------------------------------------#

```