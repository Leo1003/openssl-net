﻿// Copyright (c) 2006-2007 Frank Laub
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

using OpenSSL.Native;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace OpenSSL.Core
{
    /// <summary>
    /// V_CRYPTO_MDEBUG_*
    /// </summary>
    [Flags]
    public enum DebugOptions
    {
        /// <summary>
        /// V_CRYPTO_MDEBUG_TIME
        /// </summary>
        Time = 0x01,

        /// <summary>
        /// V_CRYPTO_MDEBUG_THREAD
        /// </summary>
        Thread = 0x02,

        /// <summary>
        /// V_CRYPTO_MDEBUG_ALL
        /// </summary>
        All = Time | Thread,
    }

    /// <summary>
    /// CRYPTO_MEM_CHECK_*
    /// </summary>
    public enum MemoryCheck
    {
        /// <summary>
        /// CRYPTO_MEM_CHECK_OFF
        /// for applications
        /// </summary>
        Off = 0x00,

        /// <summary>
        /// CRYPTO_MEM_CHECK_ON
        /// for applications
        /// </summary>
        On = 0x01,

        /// <summary>
        /// CRYPTO_MEM_CHECK_ENABLE
        /// for library-internal use
        /// </summary>
        Enable = 0x02,

        /// <summary>
        /// CRYPTO_MEM_CHECK_DISABLE
        /// for library-internal use
        /// </summary>
        Disable = 0x03,
    }

    /// <summary>
    /// Exposes the CRYPTO_* functions
    /// </summary>
    public class CryptoUtil
    {
        /// <summary>
        /// Returns RC4_options()
        /// </summary>
        public static string RC4_Options {
            get { return NativeMethods.StaticString(NativeMethods.RC4_options()); }
        }

        /// <summary>
        /// Returns DES_options()
        /// </summary>
        public static string DES_Options {
            get { return NativeMethods.StaticString(NativeMethods.DES_options()); }
        }

        /// <summary>
        /// Returns idea_options()
        /// </summary>
        public static string Idea_Options {
            get { return NativeMethods.StaticString(NativeMethods.IDEA_options()); }
        }

        /// <summary>
        /// Returns BF_options()
        /// </summary>
        public static string Blowfish_Options {
            get { return NativeMethods.StaticString(NativeMethods.BF_options()); }
        }

        /// <summary>
        /// Calls ERR_clear_error()
        /// </summary>
        public static void ClearErrors()
        {
            NativeMethods.ERR_clear_error();
        }

        /// <summary>
        /// Calls ERR_print_errors_cb()
        /// </summary>
        /// <value>The errors.</value>
        public static List<string> GetErrors()
        {
            var errors = new List<string>();
            NativeMethods.ERR_print_errors_cb((IntPtr str, UIntPtr len, IntPtr u) => {
                errors.Add(NativeMethods.StaticString(str));
                return 0;
            }, IntPtr.Zero);
            return errors;
        }
    }
}
