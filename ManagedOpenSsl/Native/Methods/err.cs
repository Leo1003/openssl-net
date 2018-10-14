using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int err_cb(IntPtr str, uint len, IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint ERR_get_error();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ERR_error_string_n(uint e, byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ERR_lib_error_string(uint e);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ERR_func_error_string(uint e);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ERR_reason_error_string(uint e);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ERR_clear_error();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ERR_print_errors_cb(err_cb cb, IntPtr u);
    }
}
