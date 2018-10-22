using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public extern static IntPtr BIO_new_file(string filename, string mode);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BIO_new_mem_buf(byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BIO_s_mem();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BIO_f_md();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BIO_f_null();

        public static void BIO_set_md(IntPtr bp, IntPtr md)
        {
            NativeMethods.ExpectSuccess(BIO_ctrl(bp, BIO_Ctrl.C_SET_MD, 0, md));
        }

        public static IntPtr BIO_get_md(IntPtr bp)
        {
            var ptr = Marshal.AllocHGlobal(4);

            try {
                ExpectSuccess(BIO_ctrl(bp, BIO_Ctrl.C_GET_MD, 0, ptr));
                return Marshal.ReadIntPtr(ptr);
            } finally {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public static IntPtr BIO_get_md_ctx(IntPtr bp)
        {
            var ptr = Marshal.AllocHGlobal(4);

            try {
                ExpectSuccess(BIO_ctrl(bp, BIO_Ctrl.C_GET_MD_CTX, 0, ptr));
                return Marshal.ReadIntPtr(ptr);
            } finally {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public static void BIO_set_md_ctx(IntPtr bp, IntPtr mdcp)
        {
            NativeMethods.ExpectSuccess(BIO_ctrl(bp, BIO_Ctrl.C_SET_MD_CTX, 0, mdcp));
        }

        public static BIO_Close BIO_get_close(IntPtr bp)
        {
            return (BIO_Close)BIO_ctrl(bp, BIO_Ctrl.GET_CLOSE, 0, IntPtr.Zero);
        }

        public static int BIO_set_close(IntPtr bp, BIO_Close arg)
        {
            return BIO_ctrl(bp, BIO_Ctrl.SET_CLOSE, (int)arg, IntPtr.Zero);
        }

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BIO_push(IntPtr bp, IntPtr append);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BIO_ctrl(IntPtr bp, BIO_Ctrl cmd, int larg, IntPtr parg);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BIO_int_ctrl(IntPtr bp, int cmd, int larg, int parg);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BIO_new(IntPtr type);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BIO_read(IntPtr b, byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BIO_write(IntPtr b, byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BIO_puts(IntPtr b, byte[] buf);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BIO_gets(IntPtr b, byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BIO_free(IntPtr bio);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static ulong BIO_number_read(IntPtr bio);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static ulong BIO_number_written(IntPtr bio);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static UIntPtr BIO_ctrl_pending(IntPtr bio);
    }
}
