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

import sys
import os
import string
import getopt
from sys import argv

name = "Powershell Universal Programmer"
shrtname = " (Power-PUP.py)"
__version__ = "1.0"


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


def write_csfile(ps_script):

    # Open and create cs file to compile
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

    ps_input = raw_input("Enter the powershell command to execute: \n: ")
    ps_script = string.replace(ps_input, '\\', '\\\\')
    print
    write_csfile(ps_script)
    compile_exe(arch,out_exe)
    
main()