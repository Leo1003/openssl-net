﻿// Copyright (c) 2009 Ben Henderson
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
using OpenSSL.Native;
using System;

namespace OpenSSL.SSL
{
    /// <summary>
    /// Wraps the SSL_METHOD structure and methods
    /// </summary>
    public class SslMethod : Base
    {
        private SslMethod(IntPtr ptr, bool owner) :
            base(ptr, owner)
        {
        }

        /// <summary>
        /// Throws NotImplementedException()
        /// </summary>
        protected override void ReleaseHandle()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// TLS_method()
        /// </summary>
        public static readonly SslMethod TLS_method = new SslMethod(NativeMethods.TLS_method(), false);

        /// <summary>
        /// TLS_server_method()
        /// </summary>
        public static readonly SslMethod TLS_server_method = new SslMethod(NativeMethods.TLS_server_method(), false);

        /// <summary>
        /// TLS_client_method()
        /// </summary>
        public static readonly SslMethod TLS_client_method = new SslMethod(NativeMethods.TLS_client_method(), false);

        /// <summary>
        /// DTLS_method()
        /// </summary>
        public static readonly SslMethod DTLS_method = new SslMethod(NativeMethods.DTLS_method(), false);

        /// <summary>
        /// DTLS_server_method()
        /// </summary>
        public static readonly SslMethod DTLS_server_method = new SslMethod(NativeMethods.DTLS_server_method(), false);

        /// <summary>
        /// DTLS_client_method()
        /// </summary>
        public static readonly SslMethod DTLS_client_method = new SslMethod(NativeMethods.DTLS_client_method(), false);

    }
}
