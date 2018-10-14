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
