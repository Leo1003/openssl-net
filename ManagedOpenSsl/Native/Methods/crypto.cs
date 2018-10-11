using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        #region Version

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OpenSSL_version(int type);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint OpenSSL_version_num();

        #endregion

        #region MemoryManagement

        /// <summary>
        /// #define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)
        /// </summary>
        /// <param name="cbSize"></param>
        /// <returns></returns>
        public static IntPtr OPENSSL_malloc(int cbSize)
        {
            StackFrame callStack = new StackFrame(1, true);
            return CRYPTO_malloc(cbSize, callStack.GetFileName(), callStack.GetFileLineNumber());
        }

        /// <summary>
        /// #define OPENSSL_free(addr) CRYPTO_free(addr)
        /// </summary>
        /// <param name="p"></param>
        public static void OPENSSL_free(IntPtr p)
        {
            CRYPTO_free(p);
        }

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void CRYPTO_free(IntPtr p);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr CRYPTO_malloc(int num, string file, int line);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr MallocFunctionPtr(uint num, IntPtr file, int line);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr ReallocFunctionPtr(IntPtr addr, uint num, IntPtr file, int line);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void FreeFunctionPtr(IntPtr addr);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int CRYPTO_set_mem_functions(
            MallocFunctionPtr m,
            ReallocFunctionPtr r,
            FreeFunctionPtr f
        );

        #endregion

        #region ThreadLock

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr CRYPTO_THREAD_lock_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int CRYPTO_THREAD_read_lock(IntPtr lck);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int CRYPTO_THREAD_write_lock(IntPtr lck);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int CRYPTO_THREAD_unlock(IntPtr lck);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void CRYPTO_THREAD_lock_free(IntPtr lck);

        #endregion

        #region FIPS

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int FIPS_mode_set(int onoff);

        #endregion
    }
}
