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

using System;

namespace OpenSSL.SSL
{
    /// <summary>
    ///
    /// </summary>
    public enum CipherAlgorithmType
    {
        /// <summary>
        ///
        /// </summary>
        None,
        /// <summary>
        ///
        /// </summary>
        Rc2,
        /// <summary>
        ///
        /// </summary>
        Rc4,
        /// <summary>
        ///
        /// </summary>
        Des,
        /// <summary>
        ///
        /// </summary>
        Idea,
        /// <summary>
        ///
        /// </summary>
        Fortezza,
        /// <summary>
        ///
        /// </summary>
        Camellia128,
        /// <summary>
        ///
        /// </summary>
        Camellia256,
        /// <summary>
        ///
        /// </summary>
        Seed,
        /// <summary>
        ///
        /// </summary>
        TripleDes,
        /// <summary>
        ///
        /// </summary>
        Aes,
        /// <summary>
        ///
        /// </summary>
        Aes128,
        /// <summary>
        ///
        /// </summary>
        Aes192,
        /// <summary>
        ///
        /// </summary>
        Aes256
    }

    /// <summary>
    ///
    /// </summary>
    public enum HashAlgorithmType
    {
        /// <summary>
        ///
        /// </summary>
        None,
        /// <summary>
        ///
        /// </summary>
        Md5,
        /// <summary>
        ///
        /// </summary>
        Sha1
    }

    /// <summary>
    ///
    /// </summary>
    public enum ExchangeAlgorithmType
    {
        /// <summary>
        ///
        /// </summary>
        None,
        /// <summary>
        ///
        /// </summary>
        RsaSign,
        /// <summary>
        ///
        /// </summary>
        RsaKeyX,
        /// <summary>
        ///
        /// </summary>
        DiffieHellman,
        /// <summary>
        ///
        /// </summary>
        Kerberos,
        /// <summary>
        ///
        /// </summary>
        Fortezza,
        /// <summary>
        ///
        /// </summary>
        ECDiffieHellman
    }

    /// <summary>
    ///
    /// </summary>
    [Flags]
    public enum SslProtocols
    {
        /// <summary>
        ///
        /// </summary>
        None = 0,
        /// <summary>
        ///
        /// </summary>
        Ssl2 = 1,
        /// <summary>
        ///
        /// </summary>
        Ssl3 = 2,
        /// <summary>
        ///
        /// </summary>
        Tls1 = 4,
        /// <summary>
        ///
        /// </summary>
        Tls1_1 = 8,
        /// <summary>
        ///
        /// </summary>
        Tls1_2 = 16,
        /// <summary>
        ///
        /// </summary>
        Tls1_3 = 32,
        /// <summary>
        ///
        /// </summary>
        Default = 1024
    }

    /// <summary>
    ///
    /// </summary>
    [Flags]
    public enum SslStrength
    {
        /// <summary>
        ///
        /// </summary>
        High = 4,   //256
                    /// <summary>
                    ///
                    /// </summary>
        Medium = 2, //128
                    /// <summary>
                    ///
                    /// </summary>
        Low = 1,    //40
                    /// <summary>
                    ///
                    /// </summary>
        All = High | Medium | Low
    }

    /// <summary>
    /// SSL_FILETYPE_*
    /// </summary>
    public enum SslFileType
    {
        /// <summary>
        /// SSL_FILETYPE_PEM
        /// </summary>
        PEM = 1,
        /// <summary>
        /// SSL_FILETYPE_ASN1
        /// </summary>
        ASN1 = 2
    }

    enum AuthenticationMethod
    {
        None,
        Rsa,
        Dss,
        DiffieHellman,
        Kerberos,
        ECDsa
    }

    enum HandshakeState
    {
        None,
        Renegotiate,
        InProcess,
        RenegotiateInProcess,
        Complete
    }
}
