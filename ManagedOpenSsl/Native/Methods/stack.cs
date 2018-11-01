using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int OPENSSL_sk_compfunc(IntPtr a, IntPtr b);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void OPENSSL_sk_freefunc(IntPtr ptr);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr OPENSSL_sk_copyfunc(IntPtr ptr);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_new_null();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void OPENSSL_sk_free(IntPtr stack);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void OPENSSL_sk_pop_free(IntPtr stack, OPENSSL_sk_freefunc func);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_deep_copy(IntPtr stack,
                                    OPENSSL_sk_copyfunc c,
                                    OPENSSL_sk_freefunc f);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_delete(IntPtr stack, int loc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_delete_ptr(IntPtr stack, IntPtr p);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_dup(IntPtr stack);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OPENSSL_sk_find(IntPtr stack, IntPtr data);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OPENSSL_sk_num(IntPtr stack);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OPENSSL_sk_insert(IntPtr stack, IntPtr data, int where);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_shift(IntPtr stack);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OPENSSL_sk_unshift(IntPtr stack, IntPtr data);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OPENSSL_sk_push(IntPtr stack, IntPtr data);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_pop(IntPtr stack);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_value(IntPtr stack, int index);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OPENSSL_sk_set(IntPtr stack, int index, IntPtr data);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void OPENSSL_sk_zero(IntPtr stack);
    }
}
