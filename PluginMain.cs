namespace SMHackSubProcessTracer {
    using System;
    using System.Collections.Concurrent;
    using System.Diagnostics;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.InteropServices;
    using System.Threading;
    using SMHackCore;

    public class PluginMain : IPlugin {
        private readonly ConcurrentDictionary<IntPtr, int> _threadToProcessDictionary =
            new ConcurrentDictionary<IntPtr, int>();

        [SuppressMessage("ReSharper", "UnusedParameter.Local")]
        public PluginMain(ServerInterfaceProxy proxy) {
        }

        public ApiHook[] GetApiHooks() {
            return new[] {
                new ApiHook(
                    "ntdll.dll",
                    "NtCreateUserProcess",
                    proxy => new NtCreateUserProcessDelegate(
                        delegate(
                            out IntPtr processHandle,
                            out IntPtr threadHandle,
                            uint processAccess,
                            uint threadAccess,
                            IntPtr processAttributes,
                            IntPtr threadAttributes,
                            uint processFlags,
                            uint threadFlags,
                            IntPtr parameters,
                            IntPtr unknown,
                            IntPtr list) {
                            var ret = NtCreateUserProcess(
                                out processHandle,
                                out threadHandle,
                                processAccess,
                                threadAccess,
                                processAttributes,
                                threadAttributes,
                                processFlags,
                                threadFlags,
                                parameters,
                                unknown,
                                list);
                            var pid = GetProcessId(processHandle);
                            var process = Process.GetProcessById(pid);
                            proxy.DoLog(
                                new Tracing {
                                    Action = "Tracing",
                                    Pid = pid,
                                    Name = process.ProcessName
                                });
                            _threadToProcessDictionary.GetOrAdd(threadHandle, pid);
                            return ret;
                        })),
                new ApiHook(
                    "ntdll.dll",
                    "NtResumeThread",
                    proxy => new NtResumeThreadDelegate(
                        delegate(
                            IntPtr hthread,
                            IntPtr pcount) {
                            if (!_threadToProcessDictionary.ContainsKey(hthread))
                                return NtResumeThread(hthread, pcount);
                            while (true) {
                                if (_threadToProcessDictionary.TryRemove(hthread, out var pid)) {
                                    proxy.DoInject(pid);
                                    break;
                                }
                                Thread.Yield();
                            }
                            return 0;
                        }))
            };
        }

        public void Init() { }

        [DllImport("ntdll.dll")]
        internal static extern uint NtCreateUserProcess(
            out IntPtr processHandle,
            out IntPtr threadHandle,
            uint processDesiredAccess,
            uint threadDesiredAccess,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            uint processFlags,
            uint threadFlags,
            IntPtr processParameters,
            IntPtr unknown,
            IntPtr attributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int GetProcessId(IntPtr processHandle);

        [DllImport("ntdll.dll")]
        internal static extern int NtResumeThread(
            IntPtr hthread,
            IntPtr count
        );

        [Serializable]
        public struct Tracing {
            public string Action;
            public int Pid;
            public string Name;
        }

        internal delegate uint NtCreateUserProcessDelegate(
            out IntPtr processHandle,
            out IntPtr threadHandle,
            uint processDesiredAccess,
            uint threadDesiredAccess,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            uint processFlags,
            uint threadFlags,
            IntPtr processParameters,
            IntPtr unknown,
            IntPtr attributeList);

        internal delegate int NtResumeThreadDelegate(
            IntPtr hthread,
            IntPtr pcount
        );
    }
}