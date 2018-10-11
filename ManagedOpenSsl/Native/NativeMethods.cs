// Copyright (c) 2006-2012 Frank Laub
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using OpenSSL.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace OpenSSL.Native
{
    /// <summary>
    /// This is the low-level C-style interface to the crypto API.
    /// Use this interface with caution.
    /// </summary>
    internal partial class NativeMethods
    {
        #region Delegates

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int err_cb(IntPtr str, uint len, IntPtr u);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int pem_password_cb(IntPtr buf, int size, int rwflag, IntPtr userdata);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int GeneratorHandler(int p, int n, IntPtr arg);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void ObjectNameHandler(IntPtr name, IntPtr arg);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int VerifyCertCallback(int ok, IntPtr x509_store_ctx);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int client_cert_cb(IntPtr ssl, out IntPtr x509, out IntPtr pkey);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int alpn_cb(
            IntPtr ssl,
            out string selProto,
            out byte selProtoLen,
            IntPtr inProtos,
            int inProtosLen,
            IntPtr arg
        );

        #endregion

        #region Initialization

        static NativeMethods()
        {
            var lib = Core.Version.Library;
            var wrapper = Core.Version.Wrapper;
            if (lib.Raw < wrapper.Raw)
                throw new Exception(string.Format("Invalid version of {0}, expecting {1}, got: {2}",
                    DLLNAME, wrapper, lib));

#if MEMORY_TRACKER
			MemoryTracker.Init();
#endif

            // Enable FIPS mode
            if (FIPS.Enabled) {
                if (FIPS_mode_set(1) == 0) {
                    throw new Exception("Failed to initialize FIPS mode");
                }
            }

            // Initialize library
            ExpectSuccess(OPENSSL_init_ssl(OpenSSL_Init.LOAD_SSL_STRINGS |
                OpenSSL_Init.LOAD_CRYPTO_STRINGS, IntPtr.Zero));
            ExpectSuccess(OPENSSL_init_crypto(OpenSSL_Init.LOAD_CRYPTO_STRINGS |
                OpenSSL_Init.ADD_ALL_CIPHERS |
                OpenSSL_Init.ADD_ALL_DIGESTS, IntPtr.Zero));

            var seed = new byte[128];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(seed);
            RAND_seed(seed, seed.Length);
        }

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OPENSSL_init_crypto(OpenSSL_Init opts, IntPtr settings);

        #endregion

        #region Version

        // 1.1.1 Release
        public const uint Wrapper = 0x1010100F;

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RC4_options();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DES_options();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr IDEA_options();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BF_options();

        #endregion

        #region SHA

        public const int SHA_DIGEST_LENGTH = 20;

        #endregion

        #region X509_REQ

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_REQ_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_set_version(IntPtr x, int version);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_set_pubkey(IntPtr x, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_REQ_get_pubkey(IntPtr req);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_set_subject_name(IntPtr x, IntPtr name);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_sign(IntPtr x, IntPtr pkey, IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_verify(IntPtr x, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_digest(IntPtr data, IntPtr type, byte[] md, ref uint len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_REQ_free(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_REQ_to_X509(IntPtr r, int days, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_print_ex(IntPtr bp, IntPtr x, uint nmflag, uint cflag);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_REQ_print(IntPtr bp, IntPtr x);

        #endregion

        #region X509

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_new();

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
        public extern static IntPtr X509_get_subject_name(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set1_notBefore(IntPtr x, IntPtr tm);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set1_notAfter(IntPtr x, IntPtr tm);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_set_pubkey(IntPtr x, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_get_pubkey(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_free(IntPtr x);

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

        #region X509_EXTENSION

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_EXTENSION_free(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_dup(IntPtr ex);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509V3_EXT_print(IntPtr bio, IntPtr ext, uint flag, int indent);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509V3_EXT_get_nid(int nid);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_add_ext(IntPtr x, IntPtr ex, int loc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_add1_ext_i2d(IntPtr x, int nid, byte[] value, int crit, uint flags);

        //X509_EXTENSION* X509V3_EXT_conf_nid(LHASH* conf, X509V3_CTX* ctx, int ext_nid, char* value);
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509V3_EXT_conf_nid(IntPtr conf, IntPtr ctx, int ext_nid, string value);

        //X509_EXTENSION* X509_EXTENSION_create_by_NID(X509_EXTENSION** ex, int nid, int crit, ASN1_OCTET_STRING* data);
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_create_by_NID(IntPtr ex, int nid, int crit, IntPtr data);

        //X509_EXTENSION* X509_EXTENSION_create_by_OBJ(X509_EXTENSION** ex, ASN1_OBJECT* obj, int crit, ASN1_OCTET_STRING* data);
        //int X509_EXTENSION_set_object(X509_EXTENSION* ex, ASN1_OBJECT* obj);
        //int X509_EXTENSION_set_critical(X509_EXTENSION* ex, int crit);
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_EXTENSION_set_critical(IntPtr ex, int crit);

        //int X509_EXTENSION_set_data(X509_EXTENSION* ex, ASN1_OCTET_STRING* data);
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_EXTENSION_set_data(IntPtr ex, IntPtr data);

        //ASN1_OBJECT* X509_EXTENSION_get_object(X509_EXTENSION* ex);
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_get_object(IntPtr ex);

        //ASN1_OCTET_STRING* X509_EXTENSION_get_data(X509_EXTENSION* ne);
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_EXTENSION_get_data(IntPtr ne);

        //int X509_EXTENSION_get_critical(X509_EXTENSION* ex);
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_EXTENSION_get_critical(IntPtr ex);

        #endregion

        #region X509_STORE

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509_STORE_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_add_cert(IntPtr ctx, IntPtr x);

        //[DllImport(DLLNAME, CallingConvention=CallingConvention.Cdecl)]
        //void X509_STORE_set_flags();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_STORE_free(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509_STORE_up_ref(IntPtr x);

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

        #region X509_INFO

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509_INFO_free(IntPtr a);

        #endregion

        #region X509_NAME

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

        #region PEM

        #region X509

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PEM_write_bio_X509(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_X509(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PEM_read_bio_PKCS7(IntPtr bp, IntPtr x, pem_password_cb cb, IntPtr u);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr d2i_PKCS7_bio(IntPtr bp, IntPtr p7);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void PKCS7_free(IntPtr p7);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr d2i_PKCS12_bio(IntPtr bp, IntPtr p12);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int i2d_PKCS12_bio(IntPtr bp, IntPtr p12);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PKCS12_create(
            string pass,
            string name,
            IntPtr pkey,
            IntPtr cert,
            IntPtr ca,
            int nid_key,
            int nid_cert,
            int iter,
            int mac_iter,
            int keytype);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PKCS12_parse(IntPtr p12, string pass, out IntPtr pkey, out IntPtr cert, out IntPtr ca);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void PKCS12_free(IntPtr p12);

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

        #endregion

        #region EC

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_get_builtin_curves(IntPtr r, int nitems);

        #region EC_METHOD

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GFp_simple_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GFp_mont_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GFp_nist_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GF2m_simple_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_METHOD_get_field_type(IntPtr meth);

        #endregion

        #region EC_GROUP

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_new(IntPtr meth);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_free(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_clear_free(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_copy(IntPtr dst, IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_dup(IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_method_of(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_set_generator(IntPtr group, IntPtr generator, IntPtr order, IntPtr cofactor);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_get0_generator(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_order(IntPtr group, IntPtr order, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_cofactor(IntPtr group, IntPtr cofactor, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_set_curve_name(IntPtr group, int nid);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_curve_name(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_set_asn1_flag(IntPtr group, int flag);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_asn1_flag(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_set_point_conversion_form(IntPtr x, int y);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_point_conversion_form(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static byte[] EC_GROUP_get0_seed(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_seed_len(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_set_seed(IntPtr x, byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_set_curve(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_curve(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_degree(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_check(IntPtr group, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_check_discriminant(IntPtr group, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_cmp(IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_new_curve_GFp(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_new_curve_GF2m(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_new_by_curve_name(int nid);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_precompute_mult(IntPtr group, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_have_precompute_mult(IntPtr group);

        #endregion

        #region EC_POINT

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_new(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_POINT_free(IntPtr point);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_POINT_clear_free(IntPtr point);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_copy(IntPtr dst, IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_dup(IntPtr src, IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_method_of(IntPtr point);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_set_to_infinity(IntPtr group, IntPtr point);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_set_Jprojective_coordinates_GFp(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            IntPtr y,
            IntPtr z,
            IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_get_Jprojective_coordinates_GFp(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            IntPtr y,
            IntPtr z,
            IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_set_affine_coordinates(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_get_affine_coordinates(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_set_compressed_coordinates(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            int y_bit,
            IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_point2oct(IntPtr group, IntPtr p, int form, byte[] buf, int len, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_oct2point(IntPtr group, IntPtr p, byte[] buf, int len, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_point2bn(IntPtr a, IntPtr b, int form, IntPtr c, IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_bn2point(IntPtr a, IntPtr b, IntPtr c, IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static string EC_POINT_point2hex(IntPtr a, IntPtr b, int form, IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_hex2point(IntPtr a, string s, IntPtr b, IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_add(IntPtr group, IntPtr r, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_dbl(IntPtr group, IntPtr r, IntPtr a, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_invert(IntPtr group, IntPtr a, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_is_at_infinity(IntPtr group, IntPtr p);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_is_on_curve(IntPtr group, IntPtr point, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_cmp(IntPtr group, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_make_affine(IntPtr a, IntPtr b, IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINTs_make_affine(IntPtr a, int num, IntPtr[] b, IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINTs_mul(IntPtr group, IntPtr r, IntPtr n, int num, IntPtr[] p, IntPtr[] m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_mul(IntPtr group, IntPtr r, IntPtr n, IntPtr q, IntPtr m, IntPtr ctx);

        #endregion

        #region EC_KEY

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr EC_KEY_dup_func(IntPtr x);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void EC_KEY_free_func(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_new_by_curve_name(int nid);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_KEY_free(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_copy(IntPtr dst, IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_dup(IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_up_ref(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_get0_group(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_set_group(IntPtr key, IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_get0_private_key(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_set_private_key(IntPtr key, IntPtr prv);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_get0_public_key(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_set_public_key(IntPtr key, IntPtr pub);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint EC_KEY_get_enc_flags(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_KEY_set_enc_flags(IntPtr x, uint y);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_get_conv_form(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_KEY_set_conv_form(IntPtr x, int y);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_KEY_set_asn1_flag(IntPtr x, int y);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_precompute_mult(IntPtr key, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_generate_key(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_check_key(IntPtr key);

        #endregion

        #region ECDSA

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ECDSA_SIG_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ECDSA_SIG_free(IntPtr sig);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int i2d_ECDSA_SIG(IntPtr sig, byte[] pp);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr d2i_ECDSA_SIG(IntPtr sig, byte[] pp, long len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ECDSA_do_sign(byte[] dgst, int dgst_len, IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ECDSA_do_sign_ex(byte[] dgst, int dgstlen, IntPtr kinv, IntPtr rp, IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_do_verify(byte[] dgst, int dgst_len, IntPtr sig, IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_size(IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_sign_setup(IntPtr eckey, IntPtr ctx, IntPtr kinv, IntPtr rp);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_sign(int type, byte[] dgst, int dgstlen, byte[] sig, ref uint siglen, IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_sign_ex(
            int type,
            byte[] dgst,
            int dgstlen,
            byte[] sig,
            ref uint siglen,
            IntPtr kinv,
            IntPtr rp,
            IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_verify(int type, byte[] dgst, int dgstlen, byte[] sig, int siglen, IntPtr eckey);

        #endregion

        #region ECDH
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr ECDH_KDF([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pin,
                                        int inlen,
                                        IntPtr pout,
                                        ref int outlen);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDH_compute_key(byte[] pout, int outlen, IntPtr pub_key, IntPtr ecdh, ECDH_KDF kdf);
        #endregion

        #endregion

        #region NCONF

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509V3_set_ctx(
            IntPtr ctx,
            IntPtr issuer,
            IntPtr subject,
            IntPtr req,
            IntPtr crl,
            int flags);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509V3_set_nconf(IntPtr ctx, IntPtr conf);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509V3_EXT_add_nconf(IntPtr conf, IntPtr ctx, byte[] section, IntPtr cert);

        #endregion

        #region SSL Routines

        #region Initialization

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OPENSSL_init_ssl(OpenSSL_Init opts, IntPtr settings);

        #endregion

        #region SSL Methods
        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr TLS_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr TLS_server_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr TLS_client_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DTLS_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DTLS_client_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DTLS_server_method();
        #endregion

        #region SSL_CTX

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CTX_new(IntPtr sslMethod);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_free(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_ctrl(IntPtr ctx, int cmd, int arg, IntPtr parg);

        public const int SSL_CTRL_OPTIONS = 32;
        public const int SSL_CTRL_MODE = 33;

        public const int SSL_OP_MICROSOFT_SESS_ID_BUG = 0x00000001;
        public const int SSL_OP_NETSCAPE_CHALLENGE_BUG = 0x00000002;
        public const int SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000008;
        public const int SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x00000010;
        public const int SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER = 0x00000020;
        /* no effect since 0.9.7h and 0.9.8b */
        public const int SSL_OP_MSIE_SSLV2_RSA_PADDING = 0x00000040;
        public const int SSL_OP_SSLEAY_080_CLIENT_DH_BUG = 0x00000080;
        public const int SSL_OP_TLS_D5_BUG = 0x00000100;

        /* Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added
		 * in OpenSSL 0.9.6d.  Usually (depending on the application protocol)
		 * the workaround is not needed.  Unfortunately some broken SSL/TLS
		 * implementations cannot handle it at all, which is why we include
		 * it in SSL_OP_ALL. */
        /* added in 0.9.6e */
        public const int SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800;

        /* SSL_OP_ALL: various bug workarounds that should be rather harmless.
		 *             This used to be 0x000FFFFFL before 0.9.7. */
        public const int SSL_OP_ALL = (0x00000FFF ^ SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG);

        /* As server, disallow session resumption on renegotiation */
        public const int SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000;
        /* If set, always create a new key when using tmp_dh parameters */
        public const int SSL_OP_SINGLE_DH_USE = 0x00100000;
        /* Set to always use the tmp_rsa key when doing RSA operations,
		 * even when this violates protocol specs */
        public const int SSL_OP_EPHEMERAL_RSA = 0x00200000;
        /* Set on servers to choose the cipher according to the server's
		 * preferences */
        public const int SSL_OP_CIPHER_SERVER_PREFERENCE = 0x00400000;
        /* If set, a server will allow a client to issue a SSLv3.0 version number
		 * as latest version supported in the premaster secret, even when TLSv1.0
		 * (version 3.1) was announced in the client hello. Normally this is
		 * forbidden to prevent version rollback attacks. */
        public const int SSL_OP_TLS_ROLLBACK_BUG = 0x00800000;

        public const int SSL_OP_NO_SSLv2 = 0x01000000;
        public const int SSL_OP_NO_SSLv3 = 0x02000000;
        public const int SSL_OP_NO_TLSv1 = 0x04000000;

        /* The next flag deliberately changes the ciphertest, this is a check
		 * for the PKCS#1 attack */
        public const int SSL_OP_PKCS1_CHECK_1 = 0x08000000;
        public const int SSL_OP_PKCS1_CHECK_2 = 0x10000000;
        public const int SSL_OP_NETSCAPE_CA_DN_BUG = 0x20000000;
        public const int SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x40000000;


        /* Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
		 * when just a single record has been written): */
        public const int SSL_MODE_ENABLE_PARTIAL_WRITE = 0x00000001;
        /* Make it possible to retry SSL_write() with changed buffer location
		 * (buffer contents must stay the same!); this is not the default to avoid
		 * the misconception that non-blocking SSL_write() behaves like
		 * non-blocking write(): */
        public const int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 0x00000002;
        /* Never bother the application with retries if the transport
		 * is blocking: */
        public const int SSL_MODE_AUTO_RETRY = 0x00000004;
        /* Don't attempt to automatically build certificate chain */
        public const int SSL_MODE_NO_AUTO_CHAIN = 0x00000008;

        /// <summary>
        /// #define SSL_CTX_ctrl in ssl.h - calls SSL_CTX_ctrl()
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="op"></param>
        /// <returns></returns>
        public static int SSL_CTX_set_mode(IntPtr ctx, int op)
        {
            return SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_get_mode in ssl.h - calls SSL_CTX_ctrl
        /// </summary>
        /// <param name="ctx"></param>
        /// <returns></returns>
        public static int SSL_CTX_get_mode(IntPtr ctx)
        {
            return SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, 0, IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_set_options in ssl.h - calls SSL_CTX_ctrl
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="op"></param>
        /// <returns></returns>
        public static int SSL_CTX_set_options(IntPtr ctx, int op)
        {
            return SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, op, IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_get_options in ssl.h - calls SSL_CTX_ctrl
        /// </summary>
        /// <param name="ctx"></param>
        /// <returns>Int32 representation of options set in the context</returns>
        public static int SSL_CTX_get_options(IntPtr ctx)
        {
            return SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, 0, IntPtr.Zero);
        }

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_cert_store(IntPtr ctx, IntPtr cert_store);

        public const int SSL_VERIFY_NONE = 0x00;
        public const int SSL_VERIFY_PEER = 0x01;
        public const int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
        public const int SSL_VERIFY_CLIENT_ONCE = 0x04;

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_verify(IntPtr ctx, int mode, VerifyCertCallback callback);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_verify_depth(IntPtr ctx, int depth);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_client_CA_list(IntPtr ctx, IntPtr name_list);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CTX_get_client_CA_list(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_load_verify_locations(IntPtr ctx, string file, string path);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_set_default_verify_paths(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_set_cipher_list(IntPtr ctx, string cipher_string);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_certificate_chain_file(IntPtr ctx, string file);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_certificate(IntPtr ctx, IntPtr cert);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_PrivateKey(IntPtr ctx, IntPtr pkey);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_check_private_key(IntPtr ctx);

        public const int SSL_MAX_SID_CTX_LENGTH = 32;

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_set_session_id_context(IntPtr ctx, byte[] sid_ctx, uint sid_ctx_len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_default_passwd_cb_userdata(IntPtr ssl, IntPtr data);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_default_passwd_cb(IntPtr ssl, pem_password_cb callback);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_client_cert_cb(IntPtr ssl_ctx, client_cert_cb callback);

        #endregion

        #region SSL functions

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static string SSL_CIPHER_description(IntPtr ssl_cipher, byte[] buf, int buf_len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CIPHER_get_name(IntPtr ssl_cipher);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CIPHER_get_bits(IntPtr ssl_cipher, out int alg_bits);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CIPHER_get_version(IntPtr ssl_cipher);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_current_cipher(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_ciphers(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_get_verify_result(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_set_verify_result(IntPtr ssl, int v);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_peer_certificate(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_get_error(IntPtr ssl, int ret_code);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_accept(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_shutdown(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_write(IntPtr ssl, byte[] buf, int len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_read(IntPtr ssl, byte[] buf, int len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_renegotiate(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_set_session_id_context(IntPtr ssl, byte[] sid_ctx, uint sid_ctx_len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_do_handshake(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_connect_state(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_accept_state(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_connect(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_new(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_free(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static OpenSSL_HandshakeState SSL_get_state(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_bio(IntPtr ssl, IntPtr read_bio, IntPtr write_bio);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_use_certificate_file(IntPtr ssl, string file, int type);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_use_PrivateKey_file(IntPtr ssl, string file, int type);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_clear(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_load_client_CA_file(string file);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_client_CA_list(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_client_CA_list(IntPtr ssl, IntPtr name_list);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_certificate(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_use_certificate(IntPtr ssl, IntPtr x509);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_use_PrivateKey(IntPtr ssl, IntPtr evp_pkey);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_ctrl(IntPtr ssl, int cmd, int larg, IntPtr parg);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SSL_get_servername(IntPtr s, int type);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_get_servername_type(IntPtr s);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SSL_get_session(IntPtr s);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_CTX_callback_ctrl(IntPtr ctx, int cmd, IntPtr cb);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_CTX_set_alpn_protos(IntPtr ctx, byte[] protos, UInt32 protos_len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_get0_alpn_selected(IntPtr ssl, out IntPtr data, out int len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_CTX_set_alpn_select_cb(IntPtr ctx, alpn_cb alpnCb, IntPtr arg);

        #endregion

        #endregion

        #region Utilities

        public static string StaticString(IntPtr ptr)
        {
            return Marshal.PtrToStringAnsi(ptr);
        }

        public static string PtrToStringAnsi(IntPtr ptr, bool hasOwnership)
        {
            var len = 0;
            for (var i = 0; i < 1024; i++, len++) {
                var octet = Marshal.ReadByte(ptr, i);
                if (octet == 0)
                    break;
            }

            if (len == 1024)
                return "Invalid string";

            var buf = new byte[len];
            Marshal.Copy(ptr, buf, 0, len);
            if (hasOwnership)
                NativeMethods.OPENSSL_free(ptr);

            return Encoding.ASCII.GetString(buf, 0, len);
        }

        public static IntPtr ExpectNonNull(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                throw new OpenSslException();

            return ptr;
        }

        public static int ExpectSuccess(int ret)
        {
            if (ret <= 0)
                throw new OpenSslException();

            return ret;
        }

        public static int TextToNID(string text)
        {
            var nid = NativeMethods.OBJ_txt2nid(text);

            if (nid == NativeMethods.NID_undef)
                throw new OpenSslException();

            return nid;
        }

        #endregion
    }


}
