using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        #region X509

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_up_ref(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_free(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_dup(IntPtr x509);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_cmp(IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_sign(IntPtr x, IntPtr pkey, IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_check_private_key(IntPtr x509, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_verify(IntPtr x, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_pubkey_digest(IntPtr data, IntPtr type, byte[] md, ref uint len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_digest(IntPtr data, IntPtr type, byte[] md, ref uint len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_get0_extensions(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_get_version(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set_version(IntPtr x, int version);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set_serialNumber(IntPtr x, IntPtr serial);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_get_serialNumber(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set_issuer_name(IntPtr x, IntPtr name);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_get_issuer_name(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set_subject_name(IntPtr x, IntPtr name);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_get_subject_name(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set1_notBefore(IntPtr x, IntPtr tm);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_get0_notBefore(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set1_notAfter(IntPtr x, IntPtr tm);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_get0_notAfter(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set_pubkey(IntPtr x, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_get_pubkey(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_verify_cert(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_verify_cert_error_string(int n);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_to_X509_REQ(IntPtr x, IntPtr pkey, IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_print_ex(IntPtr bp, IntPtr x, uint nmflag, uint cflag);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_print(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_find_by_issuer_and_serial(IntPtr sk, IntPtr name, IntPtr serial);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_find_by_subject(IntPtr sk, IntPtr name);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_check_trust(IntPtr x, int id, int flags);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_time_adj(IntPtr s, int adj, ref long t);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_gmtime_adj(IntPtr s, int adj);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr d2i_X509_bio(IntPtr bp, ref IntPtr x509);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int i2d_X509_bio(IntPtr bp, IntPtr x509);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_PUBKEY_free(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_OBJECT_up_ref_count(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_OBJECT_free(IntPtr a);

        #endregion

        #region X509_REQ

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_REQ_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_REQ_free(IntPtr req);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_set_version(IntPtr req, int version);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_get_version(IntPtr req);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_set_pubkey(IntPtr req, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_REQ_get_pubkey(IntPtr req);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_REQ_get0_pubkey(IntPtr req);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_set_subject_name(IntPtr req, IntPtr name);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_REQ_get_subject_name(IntPtr req);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_sign(IntPtr req, IntPtr pkey, IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_verify(IntPtr req, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_digest(IntPtr req, IntPtr type, byte[] md, ref uint len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_REQ_to_X509(IntPtr req, int days, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_print_ex(IntPtr bp, IntPtr req, uint nmflag, uint cflag);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_print(IntPtr bp, IntPtr req);

        #endregion

        #region X509_EXTENSION

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_EXTENSION_free(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_dup(IntPtr ex);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_add_ext(IntPtr x, IntPtr ex, int loc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_add1_ext_i2d(IntPtr x, int nid, byte[] value, int crit, uint flags);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_create_by_OBJ(ref IntPtr ex, IntPtr obj, int crit, IntPtr data);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_create_by_NID(ref IntPtr ex, int nid, int crit, IntPtr data);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_EXTENSION_set_object(IntPtr ex, IntPtr obj);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_EXTENSION_set_critical(IntPtr ex, int crit);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_EXTENSION_set_data(IntPtr ex, IntPtr data);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_get_object(IntPtr ex);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_get_data(IntPtr ne);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_EXTENSION_get_critical(IntPtr ex);

        #endregion

        #region X509_INFO

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_INFO_free(IntPtr a);

        #endregion

        #region X509_NAME

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_NAME_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_NAME_free(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_NAME_dup(IntPtr xn);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_cmp(IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_entry_count(IntPtr name);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_add_entry_by_NID(
            IntPtr name,
            int nid,
            int type,
            byte[] bytes,
            int len,
            int loc,
            int set);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_add_entry_by_txt(
            IntPtr name,
            byte[] field,
            int type,
            byte[] bytes,
            int len,
            int loc,
            int set);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_get_text_by_NID(IntPtr name, int nid, byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_NAME_get_entry(IntPtr name, int loc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_NAME_delete_entry(IntPtr name, int loc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_get_index_by_NID(IntPtr name, int nid, int lastpos);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_digest(IntPtr data, IntPtr type, byte[] md, ref uint len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_NAME_oneline(IntPtr a, byte[] buf, int size);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_print(IntPtr bp, IntPtr name, int obase);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_NAME_print_ex(IntPtr bp, IntPtr nm, int indent, uint flags);

        #endregion
    }
}
