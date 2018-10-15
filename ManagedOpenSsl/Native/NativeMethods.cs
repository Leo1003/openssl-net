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
