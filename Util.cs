using System.Runtime.InteropServices;

namespace GoofyInjector
{
    internal class Util
    {
        public static uint FindProcessId(string processName)
        {
            uint pid = 0xffffffff;
        
            var snapshot = Win32.CreateToolhelp32Snapshot(SnapshotFlags.Process, 0);
            PROCESSENTRY32 process = new();
            process.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>();
        
            if (Win32.Process32FirstW(snapshot, ref process))
            {
                do
                {
                    if (process.szExeFile == processName)
                    {
                        pid = process.th32ProcessID;
                        break;
                    }
                } while (Win32.Process32NextW(snapshot, ref process));
            }
        
            Win32.CloseHandle(snapshot);
        
            return pid;
        }
    }
}
