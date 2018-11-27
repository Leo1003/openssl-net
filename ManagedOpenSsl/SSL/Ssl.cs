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
using OpenSSL.Exceptions;
using OpenSSL.Extensions;
using OpenSSL.Native;
using OpenSSL.X509;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.SSL
{
    internal enum SslError
    {
        SSL_ERROR_NONE = 0,
        SSL_ERROR_SSL = 1,
        SSL_ERROR_WANT_READ = 2,
        SSL_ERROR_WANT_WRITE = 3,
        SSL_ERROR_WANT_X509_LOOKUP = 4,
        SSL_ERROR_SYSCALL = 5,
        SSL_ERROR_ZERO_RETURN = 6,
        SSL_ERROR_WANT_CONNECT = 7,
        SSL_ERROR_WANT_ACCEPT = 8
    }

    /// <summary>
    /// Ssl.
    /// </summary>
    public class Ssl : BaseReference
    {
        #region Initialization

        /// <summary>
        /// Calls SSL_new()
        /// </summary>
        /// <param name="ctx"></param>
        internal Ssl(SslContext ctx) :
            base(NativeMethods.ExpectNonNull(NativeMethods.SSL_new(ctx.Handle)), true)
        {
        }

        internal Ssl(IntPtr ptr, bool takeOwnership) : base(ptr, takeOwnership)
        {
        }

        #endregion

        #region Properties

        internal SSL_HandshakeState State {
            get { return NativeMethods.SSL_get_state(Handle); }
        }

        /// <summary>
        /// Gets the current cipher.
        /// </summary>
        /// <value>The current cipher.</value>
        public SslCipher CurrentCipher {
            get { return new SslCipher(NativeMethods.SSL_get_current_cipher(Handle), false); }
        }

        internal Core.Stack<X509Name> CAList {
            get { return new Core.Stack<X509Name>(NativeMethods.SSL_get_client_CA_list(Handle), false); }
            set { NativeMethods.SSL_set_client_CA_list(Handle, value.Handle); }
        }

        internal X509Certificate LocalCertificate {
            get {
                var cert = NativeMethods.SSL_get_certificate(Handle);
                if (cert == IntPtr.Zero)
                    return null;
                return new X509Certificate(cert, false);
            }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.SSL_use_certificate(Handle, value.Handle));
            }
        }

        internal X509Certificate RemoteCertificate {
            get { return GetPeerCertificate(); }
        }

        internal Core.Stack<SslCipher> Ciphers {
            get { return new Core.Stack<SslCipher>(NativeMethods.SSL_get_ciphers(Handle), false); }
        }

        #endregion

        #region Methods

        internal int Accept()
        {
            return NativeMethods.SSL_accept(Handle);
        }

        internal int Connect()
        {
            return NativeMethods.SSL_connect(Handle);
        }

        internal SslError GetError(int ret_code)
        {
            return (SslError)NativeMethods.SSL_get_error(Handle, ret_code);
        }

        internal X509Certificate GetPeerCertificate()
        {
            var cert = NativeMethods.SSL_get_peer_certificate(Handle);
            if (cert == IntPtr.Zero)
                return null;
            return new X509Certificate(cert, true);
        }

        internal VerifyResult GetVerifyResult()
        {
            return (VerifyResult)NativeMethods.SSL_get_verify_result(Handle);
        }

        internal void SetVerifyResult(VerifyResult result)
        {
            NativeMethods.SSL_set_verify_result(Handle, (int)result);
        }

        internal int Shutdown()
        {
            return NativeMethods.SSL_shutdown(Handle);
        }

        internal int Write(byte[] buf, int len)
        {
            return NativeMethods.SSL_write(Handle, buf, len);
        }

        internal int Read(byte[] buf, int len)
        {
            return NativeMethods.SSL_read(Handle, buf, len);
        }

        internal int SetSessionIdContext(byte[] sid_ctx, uint sid_ctx_len)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_set_session_id_context(Handle, sid_ctx, sid_ctx_len));
        }

        internal int Renegotiate()
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_renegotiate(Handle));
        }

        internal int DoHandshake()
        {
            return NativeMethods.SSL_do_handshake(Handle);
        }

        internal void SetAcceptState()
        {
            NativeMethods.SSL_set_accept_state(Handle);
        }

        internal void SetConnectState()
        {
            NativeMethods.SSL_set_connect_state(Handle);
        }

        internal void SetBIO(BIO read, BIO write)
        {
            NativeMethods.SSL_set_bio(Handle, read.Handle, write.Handle);
        }

        internal int UseCertificateFile(string filename, SslFileType type)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_use_certificate_file(Handle, filename, (int)type));
        }

        internal int UsePrivateKeyFile(string filename, SslFileType type)
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_use_PrivateKey_file(Handle, filename, (int)type));
        }

        internal int Clear()
        {
            return NativeMethods.ExpectSuccess(NativeMethods.SSL_clear(Handle));
        }

        /// <summary>
        /// Gets the alpn selected protocol.
        /// </summary>
        /// <value>The alpn selected protocol.</value>
        public string AlpnSelectedProtocol {
            get {
                var ptr = new IntPtr();
                var len = 0;

                NativeMethods.SSL_get0_alpn_selected(Handle, out ptr, out len);

                if (ptr == IntPtr.Zero)
                    throw new AlpnException("Cant get selected protocol. See if ALPN was included into client/server hello");

                var buf = new byte[len];
                Marshal.Copy(ptr, buf, 0, len);
                return Encoding.ASCII.GetString(buf, 0, len);
            }
        }

        #endregion

        #region Overrides

        /// <summary>
        /// Calls SSL_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.SSL_free(Handle);
        }

        internal override void AddRef()
        {
            NativeMethods.ExpectSuccess(NativeMethods.SSL_up_ref(Handle));
        }

        #endregion
    }
}
