using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        #region X509_STORE

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_STORE_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_STORE_free(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_up_ref(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_lock(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_unlock(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_STORE_get0_objects(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_add_cert(IntPtr x, IntPtr x509);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_set_flags(IntPtr x, uint flags);

        #endregion

        #region X509_STORE_CTX

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_STORE_CTX_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_CTX_init(IntPtr ctx, IntPtr store, IntPtr x509, IntPtr chain);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_STORE_CTX_free(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_STORE_CTX_get_current_cert(IntPtr x509_store_ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_CTX_get_error_depth(IntPtr x509_store_ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_STORE_CTX_get0_store(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_CTX_get_error(IntPtr x509_store_ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_STORE_CTX_set_error(IntPtr x509_store_ctx, int error);

        #endregion

        #region X509_OBJECT

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_OBJECT_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_OBJECT_up_ref_count(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_OBJECT_free(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static X509_LookupType X509_OBJECT_get_type(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_OBJECT_get0_X509(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_OBJECT_set1_X509(IntPtr a, IntPtr obj);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_OBJECT_get0_X509_CRL(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_OBJECT_set1_X509_CRL(IntPtr a, IntPtr obj);

        #endregion
    }
}
