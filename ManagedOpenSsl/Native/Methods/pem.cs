using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int pem_password_cb(IntPtr buf, int size, int rwflag, IntPtr userdata);

        #region X509

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_X509(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_X509(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_PKCS7(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_PKCS8PrivateKey(
            IntPtr bp,
            IntPtr evp_pkey,
            IntPtr evp_cipher,
            IntPtr kstr,
            int klen,
            pem_password_cb cb,
            IntPtr user_data);

        #endregion

        #region X509_AUX

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_X509_AUX(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_X509_AUX(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion

        #region X509_REQ

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_X509_REQ(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_X509_REQ(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion

        #region X509_REQ_NEW

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_X509_REQ_NEW(IntPtr bp, IntPtr x);

        #endregion

        #region X509_CRL

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_X509_CRL(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_X509_CRL(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion

        #region X509Chain

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_X509_INFO_read_bio(IntPtr bp, IntPtr sk, pem_password_cb cb, IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_X509_INFO_write_bio(
            IntPtr bp,
            IntPtr xi,
            IntPtr enc,
            byte[] kstr,
            int klen,
            IntPtr cd,
            IntPtr u);

        #endregion

        #region DSA

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_DSAPrivateKey(
            IntPtr bp,
            IntPtr x,
            IntPtr enc,
            byte[] kstr,
            int klen,
            pem_password_cb cb,
            IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_DSAPrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_DSA_PUBKEY(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_DSA_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion

        #region DSAparams

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_DSAparams(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_DSAparams(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion

        #region RSA

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_RSA_PUBKEY(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_RSA_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_RSAPrivateKey(
            IntPtr bp,
            IntPtr x,
            IntPtr enc,
            byte[] kstr,
            int klen,
            pem_password_cb cb,
            IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_RSAPrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion

        #region DHparams

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_DHparams(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_DHparams(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion

        #region PrivateKey

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_PrivateKey(
            IntPtr bp,
            IntPtr x,
            IntPtr enc,
            byte[] kstr,
            int klen,
            pem_password_cb cb,
            IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_PrivateKey(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion

        #region PUBKEY

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_PUBKEY(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_PUBKEY(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        #endregion
    }
}
