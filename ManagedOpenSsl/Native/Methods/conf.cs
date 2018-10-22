using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr NCONF_new(IntPtr meth);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void NCONF_free(IntPtr conf);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void NCONF_free_data(IntPtr conf);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public extern static int NCONF_load(IntPtr conf, string file, ref int eline);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr NCONF_get_string(IntPtr conf, byte[] group, byte[] name);
    }
}
