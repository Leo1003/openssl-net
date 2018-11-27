// Copyright (c) 2009 Ben Henderson
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
using OpenSSL.Native;
using System;
using System.Runtime.InteropServices;

namespace OpenSSL.Crypto
{
    /// <summary>
    /// Wraps HMAC
    /// </summary>
    public class HMAC : Base
    {
        #region Initialization
        /// <summary>
        /// Calls HMAC_CTX_new()
        /// </summary>
        public HMAC()
            : base(NativeMethods.HMAC_CTX_new(), true)
        {

        }
        #endregion

        #region Methods

        public void Reset()
        {
            NativeMethods.ExpectSuccess(NativeMethods.HMAC_CTX_reset(Handle));
            initialized = false;
        }

        public void CopyTo(HMAC to)
        {
            NativeMethods.ExpectSuccess(NativeMethods.HMAC_CTX_copy(to.Handle, Handle));
            to.initialized = initialized;
        }

        /// <summary>
        /// Calls HMAC()
        /// </summary>
        /// <param name="digest"></param>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] Digest(MessageDigest digest, byte[] key, byte[] data)
        {
            var hash_value = new byte[digest.Size];
            uint hash_value_length = NativeMethods.EVP_MAX_MD_SIZE;
            NativeMethods.HMAC(digest.Handle, key, key.Length, data, (UIntPtr)data.Length, hash_value, ref hash_value_length);

            return hash_value;
        }

        /// <summary>
        /// Calls HMAC_Init_ex()
        /// </summary>
        /// <param name="key"></param>
        /// <param name="digest"></param>
        public void Init(byte[] key, MessageDigest digest)
        {
            NativeMethods.HMAC_Init_ex(Handle, key, key.Length, digest.Handle, IntPtr.Zero);
            initialized = true;
        }

        /// <summary>
        /// Calls HMAC_Update()
        /// </summary>
        /// <param name="data"></param>
        public void Update(byte[] data)
        {
            if (!initialized) {
                throw new InvalidOperationException("Failed to call Initialize before calling Update");
            }

            NativeMethods.HMAC_Update(Handle, data, (UIntPtr)data.Length);
        }

        /// <summary>
        /// Calls HMAC_Update()
        /// </summary>
        /// <param name="data"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        public void Update(byte[] data, int offset, int count)
        {
            if (!initialized) {
                throw new InvalidOperationException("Failed to call Initialize before calling Update");
            }
            if (data == null) {
                throw new ArgumentNullException("data");
            }
            if (count <= 0) {
                throw new ArgumentException("count must be greater than 0");
            }
            if (offset < 0) {
                throw new ArgumentException("offset must be 0 or greater");
            }
            if (data.Length < (count - offset)) {
                throw new ArgumentException("invalid length specified.  Count is greater than buffer length.");
            }

            var seg = new ArraySegment<byte>(data, offset, count);
            NativeMethods.HMAC_Update(Handle, seg.Array, (UIntPtr)seg.Count);
        }

        /// <summary>
        /// Calls HMAC_Final()
        /// </summary>
        /// <returns></returns>
        public byte[] DigestFinal()
        {
            if (!initialized) {
                throw new InvalidOperationException("Failed to call Initialize before calling DigestFinal");
            }

            var hash_value = new byte[Size];
            uint hash_value_length = NativeMethods.EVP_MAX_MD_SIZE;

            NativeMethods.HMAC_Final(Handle, hash_value, ref hash_value_length);
            return hash_value;
        }

        #endregion

        #region Properties

        public ulong Size {
            get {
                ulong ret = NativeMethods.HMAC_size(Handle).ToUInt64();
                if (ret == 0) {
                    throw new OpenSslException();
                }
                return ret;
            }
        }

        public MessageDigest MessageDigest {
            get {
                if (!initialized) {
                    throw new InvalidOperationException("Failed to call Initialize before getting MessageDigest");
                }
                return new MessageDigest(NativeMethods.HMAC_CTX_get_md(Handle), false);
            }
        }

        #endregion

        #region Overrides
        /// <summary>
        /// Calls HMAC_CTX_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            // Clean up the context
            NativeMethods.HMAC_CTX_free(Handle);
        }
        #endregion

        #region Fields
        private bool initialized = false;
        #endregion
    }
}
