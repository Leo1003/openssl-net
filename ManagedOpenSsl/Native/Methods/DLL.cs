using System;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        /// <summary>
        /// This is the name of the DLL that P/Invoke loads and tries to bind all of
        /// these native functions to.
        /// </summary>
#if _WIN64
        private const string DLLNAME = "libcrypto-1_1-x64";
        private const string SSLDLLNAME = "libssl-1_1-x64";
#endif
#if _WIN32
        private const string DLLNAME = "libcrypto-1_1";
        private const string SSLDLLNAME = "libssl-1_1";
#endif
    }
}
