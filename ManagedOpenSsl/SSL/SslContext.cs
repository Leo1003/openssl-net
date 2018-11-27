// Copyright (c) 2009 Ben Henderson
// All rights reserved.

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
using OpenSSL.Crypto;
using OpenSSL.Extensions;
using OpenSSL.Native;
using OpenSSL.X509;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace OpenSSL.SSL
{
    internal delegate int ClientCertCallbackHandler(
        Ssl ssl,
        out X509Certificate cert,
        out CryptoKey key
    );

    /// <summary>
    ///     Wraps the SST_CTX structure and methods
    /// </summary>
    internal sealed class SslContext : BaseReference
    {
        #region Members

        private AlpnExtension alpnExt;
        private ClientCertCallbackHandler OnClientCert;
        private RemoteCertificateValidationHandler OnVerifyCert;

        // hold down the thunk so it doesn't get collected
        private NativeMethods.client_cert_cb _ptrOnClientCertThunk;
        private NativeMethods.VerifyCertCallback _ptrOnVerifyCertThunk;
        private NativeMethods.alpn_cb _ptrOnAlpn;

        #endregion


        /// <summary>
        ///     Calls SSL_CTX_new()
        /// </summary>
        /// <param name="sslMethod"></param>
        /// <param name="end"></param>
        /// <param name="protoList"></param>
        public SslContext(
            SslMethod sslMethod,
            ConnectionEnd end,
            IEnumerable<string> protoList) :
            base(NativeMethods.ExpectNonNull(NativeMethods.SSL_CTX_new(sslMethod.Handle)), true)
        {
            alpnExt = new AlpnExtension(Handle, protoList);

            _ptrOnClientCertThunk = OnClientCertThunk;
            _ptrOnVerifyCertThunk = OnVerifyCertThunk;
            _ptrOnAlpn = alpnExt.AlpnCb;

            if (end == ConnectionEnd.Server) {
                NativeMethods.SSL_CTX_set_alpn_select_cb(Handle, _ptrOnAlpn, IntPtr.Zero);
            }
        }

        #region Properties

        /// <summary>
        ///     Calls SSL_CTX_set_options
        /// </summary>
        public SSL_Options Options {
            get { return NativeMethods.SSL_CTX_get_options(Handle); }
            set {
                // Because SSL_CTX_set_options() only OR the value, we should clear other bits first
                NativeMethods.SSL_CTX_clear_options(Handle, (SSL_Options)uint.MaxValue);
                NativeMethods.SSL_CTX_set_options(Handle, value);
            }
        }

        public SSL_Mode Mode {
            get { return NativeMethods.SSL_CTX_get_mode(Handle); }
            set {
                // Because SSL_CTX_set_mode() only OR the value, we should clear other bits first
                NativeMethods.SSL_CTX_clear_mode(Handle, (SSL_Mode)uint.MaxValue);
                NativeMethods.SSL_CTX_set_mode(Handle, value);
            }
        }

        #endregion

        private int OnVerifyCertThunk(int ok, IntPtr store)
        {
            var ctx = new X509StoreContext(store, false);

            // build the X509Chain from the store
            using (var chain = new X509Chain()) {
                foreach (var obj in ctx.Store.Objects) {
                    var cert = obj.Certificate;
                    if (cert != null)
                        chain.Add(cert);
                }

                // Call the managed delegate
                return OnVerifyCert(
                    this,
                    ctx.CurrentCert,
                    chain,
                    ctx.ErrorDepth,
                    (VerifyResult)ctx.Error
                ) ? 1 : 0;
            }
        }

        private int OnClientCertThunk(IntPtr ptrSsl, out IntPtr ptrCert, out IntPtr ptrKey)
        {
            ptrCert = IntPtr.Zero;
            ptrKey = IntPtr.Zero;

            var ssl = new Ssl(ptrSsl, false);
            X509Certificate cert;
            CryptoKey key;

            var ret = OnClientCert(ssl, out cert, out key);
            if (ret != 0) {
                if (cert != null)
                    ptrCert = cert.Handle;

                if (key != null)
                    ptrKey = key.Handle;
            }
            return ret;
        }

        #region Methods

        /// <summary>
        ///     Sets the certificate store for the context - calls SSL_CTX_set_cert_store
        ///     The X509Store object and contents will be freed when the context is disposed.
        ///     Ensure that the store object and it's contents have IsOwner set to false
        ///     before assigning them into the context.
        /// </summary>
        /// <param name="store"></param>
        public void SetCertificateStore(X509Store store)
        {
            store.AddRef();
            NativeMethods.SSL_CTX_set_cert_store(Handle, store.Handle);
        }

        /// <summary>
        ///     Sets the certificate verification mode and callback - calls SSL_CTX_set_verify
        /// </summary>
        /// <param name="mode"></param>
        /// <param name="callback"></param>
        public void SetVerify(SSL_Verify mode, RemoteCertificateValidationHandler callback)
        {
            OnVerifyCert = callback;
            NativeMethods.SSL_CTX_set_verify(Handle, mode, callback == null ? null : _ptrOnVerifyCertThunk);
        }

        /// <summary>
        ///     Sets the certificate verification depth - calls SSL_CTX_set_verify_depth
        /// </summary>
        /// <param name="depth"></param>
        public void SetVerifyDepth(int depth)
        {
            NativeMethods.SSL_CTX_set_verify_depth(Handle, depth);
        }

        public Core.Stack<X509Name> LoadClientCAFile(string filename)
        {
            var stack = NativeMethods.SSL_load_client_CA_file(filename);
            return new Core.Stack<X509Name>(stack, true);
        }

        /// <summary>
        ///     Calls SSL_CTX_set_client_CA_list/SSL_CTX_get_client_CA_list
        ///     The Stack and the X509Name objects contined within them
        ///     are freed when the context is disposed.  Make sure that
        ///     the Stack and X509Name objects have set IsOwner to false
        ///     before assigning them to the context.
        /// </summary>
        public Core.Stack<X509Name> CAList {
            get {
                var ptr = NativeMethods.SSL_CTX_get_client_CA_list(this.Handle);
                return new Core.Stack<X509Name>(ptr, false);
            }
            set {
                Core.Stack<X509Name> st = value.GetCopy(false);
                NativeMethods.SSL_CTX_set_client_CA_list(Handle, st.Handle);
            }
        }

        public int LoadVerifyLocations(string caFile, string caPath)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_load_verify_locations(Handle, caFile, caPath));
        }

        public int SetDefaultVerifyPaths()
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_set_default_verify_paths(Handle));
        }

        public int SetCipherList(string cipherList)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_set_cipher_list(Handle, cipherList));
        }

        public int UseCertificate(X509Certificate cert)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_use_certificate(Handle, cert.Handle));
        }

        public int UseCertificateChainFile(string filename)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_use_certificate_chain_file(Handle, filename));
        }

        public int UsePrivateKey(CryptoKey key)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_use_PrivateKey(Handle, key.Handle));
        }

        public int UsePrivateKeyFile(string filename, SslFileType type)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_use_PrivateKey_file(Handle, filename, (int)type));
        }

        public int CheckPrivateKey()
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_check_private_key(Handle));
        }

        public int SetSessionIdContext(byte[] sid_ctx)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_set_session_id_context(Handle, sid_ctx, (uint)sid_ctx.Length));
        }

        public void SetClientCertCallback(ClientCertCallbackHandler callback)
        {
            OnClientCert = callback;
            NativeMethods.SSL_CTX_set_client_cert_cb(Handle, callback == null ? null : _ptrOnClientCertThunk);
        }

        #endregion

        #region IDisposable Members

        /// <summary>
        ///     base override - calls SSL_CTX_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.SSL_CTX_free(Handle);
        }
        #endregion

        internal override void AddRef()
        {
            NativeMethods.ExpectSuccess(NativeMethods.SSL_CTX_up_ref(Handle));
        }
    }
}