using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        public const int MBSTRING_FLAG = 0x1000;

        public const int MBSTRING_ASC = MBSTRING_FLAG | 1;

        public const int ASN1_STRFLGS_RFC2253 =
            ASN1_STRFLGS_ESC_2253 |
            ASN1_STRFLGS_ESC_CTRL |
            ASN1_STRFLGS_ESC_MSB |
            ASN1_STRFLGS_UTF8_CONVERT |
            ASN1_STRFLGS_DUMP_UNKNOWN |
            ASN1_STRFLGS_DUMP_DER;

        public const int ASN1_STRFLGS_ESC_2253 = 1;
        public const int ASN1_STRFLGS_ESC_CTRL = 2;
        public const int ASN1_STRFLGS_ESC_MSB = 4;
        public const int ASN1_STRFLGS_ESC_QUOTE = 8;
        public const int ASN1_STRFLGS_UTF8_CONVERT = 0x10;
        public const int ASN1_STRFLGS_DUMP_UNKNOWN = 0x100;
        public const int ASN1_STRFLGS_DUMP_DER = 0x200;
        public const int XN_FLAG_SEP_COMMA_PLUS = (1 << 16);
        public const int XN_FLAG_FN_SN = 0;

        public const int V_ASN1_OCTET_STRING = 4;

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ASN1_INTEGER_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ASN1_INTEGER_free(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ASN1_INTEGER_set(IntPtr a, int v);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ASN1_INTEGER_get(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ASN1_TIME_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ASN1_TIME_free(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ASN1_TIME_set(IntPtr s, long t);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ASN1_UTCTIME_print(IntPtr bp, IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ASN1_STRING_type_new(int type);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ASN1_STRING_free(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ASN1_STRING_cmp(IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ASN1_STRING_dup(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ASN1_STRING_set(IntPtr str, byte[] data, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ASN1_STRING_data(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ASN1_STRING_length(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ASN1_OBJECT_free(IntPtr obj);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ASN1_d2i_bio(IntPtr xnew, IntPtr d2i, IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ASN1_i2d_bio(IntPtr i2d, IntPtr bp, IntPtr x);
    }
}
