using System.Runtime.InteropServices;

namespace GoofyInjector
{
    internal partial class Inject
    {
        public static bool LoadLibraryDLL(IntPtr hProc, string dllpath)
        {
            var hKernel = Win32.GetModuleHandle("kernel32.dll");
            if (hKernel == IntPtr.Zero)
            {
                Console.WriteLine("[DLL Injection] Failed to get kernel32.dll module address.");
                return false;
            }

            var pLoadLibraryA = Win32.GetProcAddress(hKernel, "LoadLibraryA");
            if (pLoadLibraryA == IntPtr.Zero)
            {
                Console.WriteLine("[DLL Injection] Failed to get LoadLibraryA address.");
                return false;
            }

            var pDLLPath = Win32.VirtualAllocEx(hProc, IntPtr.Zero, (uint)dllpath.Length + 1, VAAllocationType.MEM_RESERVE | VAAllocationType.MEM_COMMIT, Protection.PAGE_READWRITE);
            if (pDLLPath == IntPtr.Zero)
            {
                Console.WriteLine("[DLL Injection] Failed to allocate memory for DLLPath in target process.\n");
                return false;
            }

            var pManagedDllPath = Marshal.StringToHGlobalAnsi(dllpath);

            var writeResult = Win32.WriteProcessMemory(hProc, pDLLPath, pManagedDllPath, dllpath.Length, out var _);

            Marshal.FreeHGlobal(pManagedDllPath);

            if (writeResult == false)
            {
                Console.WriteLine("[DLL Injection] Failed to write remote process memory.\n");
                return false;
            }

            var hThread = Win32.CreateRemoteThread(hProc, IntPtr.Zero, 0, pLoadLibraryA, pDLLPath, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[DLL Injection] Failed to create remote thread.\n");
                Win32.VirtualFreeEx(hProc, pDLLPath, 0, VFAllocationType.MEM_RELEASE);
                return false;
            }

            if (Win32.WaitForSingleObject(hThread, 2000) == 0x00000000L /*WAIT_OBJECT_0*/)
            {
                Win32.VirtualFreeEx(hProc, pDLLPath, 0, VFAllocationType.MEM_RELEASE);
            }

            Win32.CloseHandle(hThread);

            Console.WriteLine("[DLL Injection] Successfully LoadLibraryA injection.\n");
            return true;
        }
    }
}
