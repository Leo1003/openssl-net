using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RAND_set_rand_method(IntPtr meth);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RAND_get_rand_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RAND_OpenSSL();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RAND_bytes(byte[] buf, int num);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void RAND_seed(byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void RAND_add(byte[] buf, int num, double entropy);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RAND_load_file(string file, int max_bytes);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RAND_write_file(string file);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static string RAND_file_name(byte[] file, UIntPtr num);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RAND_status();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RAND_poll();
    }
}
