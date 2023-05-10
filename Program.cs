
using System.Runtime.InteropServices;

namespace GoofyInjector
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            var genshinPath = args[0];
            var dllPath = args[1];
            var cmdLine = "";

            if (args.Length > 2)
                cmdLine = args[2];

            IntPtr hProcess = IntPtr.Zero, hThread = IntPtr.Zero;

            if (!OpenTargetProcess(genshinPath, cmdLine, ref hProcess, ref hThread))
            {
                Console.WriteLine("Failed to open the process.");
                return 1;
            }
            Inject.LoadLibraryDLL(hProcess, dllPath);

            Win32.ResumeThread(hThread);
            Win32.CloseHandle(hProcess);
            return 0;
        }

        public unsafe static bool OpenTargetProcess(string genshinPath, string cmdLine, ref IntPtr phProcess, ref IntPtr phThread)
        {
            var TokenRet = Win32.OpenProcessToken(Win32.GetCurrentProcess(), Win32.TOKEN_ALL_ACCESS, out var hToken);
            if (!TokenRet)
            {
                Win32.ThrowLastError(nameof(Win32.OpenProcessToken));
            }

            var pid = Util.FindProcessId("explorer.exe");
            if (pid == 0 || pid == 0xffffffff)
            {
                Console.WriteLine("Can't find 'explorer' pid!");
                return false;
            }

            var handle = Win32.OpenProcess(ProcessAccessFlags.All, false, pid);

            var lpSize = IntPtr.Zero;
            Win32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);

            var AttributeList = Marshal.AllocHGlobal(lpSize);
            var success = Win32.InitializeProcThreadAttributeList(AttributeList, 1, 0, ref lpSize);

            if (!Win32.UpdateProcThreadAttribute(AttributeList, 0, (IntPtr)0x00020000 /*PROC_THREAD_ATTRIBUTE_PARENT_PROCESS*/, (IntPtr)(&handle), (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
            {
                Win32.ThrowLastError(nameof(Win32.UpdateProcThreadAttribute));
            }

            STARTUPINFOEX si = new();
            si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            si.lpAttributeList = AttributeList;

            var result = Win32.CreateProcessAsUser(hToken, genshinPath, cmdLine, IntPtr.Zero, IntPtr.Zero, false, (uint)(CreateProcessFlags.EXTENDED_STARTUPINFO_PRESENT | CreateProcessFlags.CREATE_SUSPENDED), IntPtr.Zero, Path.GetDirectoryName(genshinPath)!, ref si, out var pi);

            if (result)
            {
                phThread = pi.hThread;
                phProcess = pi.hProcess;
            }
            else
            {
                Console.WriteLine("Failed to create the target process.");
                Win32.ThrowLastError(nameof(Win32.CreateProcessAsUser));
            }

            Win32.DeleteProcThreadAttributeList(AttributeList);
            Marshal.FreeHGlobal(AttributeList);

            return result;
        }
    }
}