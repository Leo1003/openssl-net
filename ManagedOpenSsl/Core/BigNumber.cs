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

using OpenSSL.Native;
using System;
using System.Text;

namespace OpenSSL.Core
{
    /// <summary>
    /// Wraps the BN_* set of functions.
    /// </summary>
    public class BigNumber : Base, IComparable<BigNumber>
    {
        #region Predefined Values
        /// <summary>
        /// Creates a BigNumber object by calling BN_value_one()
        /// </summary>
        public static BigNumber One = new BigNumber(NativeMethods.BN_value_one(), false);

        /// <summary>
        /// Calls BN_options()
        /// </summary>
        public static string Options {
            get { return NativeMethods.StaticString(NativeMethods.BN_options()); }
        }
        #endregion

        #region Initialization
        internal BigNumber(IntPtr ptr, bool owner) : base(ptr, owner) { }
        /// <summary>
        /// Calls BN_new()
        /// </summary>
        public BigNumber()
            : base(NativeMethods.ExpectNonNull(NativeMethods.BN_new()), true)
        {
        }

        /// <summary>
        /// Calls BN_dup() on the BigNumber passed in.
        /// </summary>
        /// <param name="rhs"></param>
        public BigNumber(BigNumber rhs)
            : base(NativeMethods.BN_dup(rhs.ptr), true)
        {
        }

        /// <summary>
        /// Creates a BigNumber by calling BN_set_word()
        /// </summary>
        /// <param name="value"></param>
        public BigNumber(uint value)
            : this()
        {
            NativeMethods.ExpectSuccess(NativeMethods.BN_set_word(ptr, value));
        }
        #endregion

        #region Conversion
        /// <summary>
        /// Calls BN_dec2bn()
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static BigNumber FromDecimalString(string str)
        {
            var buf = Encoding.ASCII.GetBytes(str);
            IntPtr ptr;

            var ret = NativeMethods.BN_dec2bn(out ptr, buf);
            if (ret <= 0)
                throw new OpenSslException();

            return new BigNumber(ptr, true);
        }

        /// <summary>
        /// Calls BN_hex2bn()
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static BigNumber FromHexString(string str)
        {
            var buf = Encoding.ASCII.GetBytes(str);
            IntPtr ptr;

            var ret = NativeMethods.BN_hex2bn(out ptr, buf);
            if (ret <= 0)
                throw new OpenSslException();

            return new BigNumber(ptr, true);
        }

        /// <summary>
        /// Calls BN_bin2bn()
        /// </summary>
        /// <param name="buf"></param>
        /// <returns></returns>
        public static BigNumber FromArray(byte[] buf)
        {
            var ptr = NativeMethods.BN_bin2bn(buf, buf.Length, IntPtr.Zero);
            return new BigNumber(NativeMethods.ExpectNonNull(ptr), true);
        }

        /// <summary>
        /// Calls BN_bn2dec()
        /// </summary>
        /// <returns></returns>
        public string ToDecimalString()
        {
            return NativeMethods.PtrToStringAnsi(NativeMethods.BN_bn2dec(ptr), true);
        }

        /// <summary>
        /// Calls BN_bn2hex()
        /// </summary>
        /// <returns></returns>
        public string ToHexString()
        {
            return NativeMethods.PtrToStringAnsi(NativeMethods.BN_bn2hex(ptr), true);
        }

        /// <summary>
        /// Calls BN_get_word()
        /// </summary>
        /// <param name="rhs"></param>
        /// <returns></returns>
        public static implicit operator uint(BigNumber rhs)
        {
            return NativeMethods.BN_get_word(rhs.ptr);
        }

        /// <summary>
        /// Creates a new BigNumber object from a uint.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static implicit operator BigNumber(uint value)
        {
            return new BigNumber(value);
        }

        /// <summary>
        /// Calls BN_bn2bin()
        /// </summary>
        /// <param name="rhs"></param>
        /// <returns></returns>
        public static implicit operator byte[] (BigNumber rhs)
        {
            var bytes = new byte[rhs.Bytes];
            NativeMethods.ExpectSuccess(NativeMethods.BN_bn2bin(rhs.ptr, bytes));

            return bytes;
        }

        /// <summary>
        /// Calls BN_bn2bin()
        /// </summary>
        /// <param name="bytes"></param>
        public void ToBytes(byte[] bytes)
        {
            NativeMethods.ExpectSuccess(NativeMethods.BN_bn2bin(ptr, bytes));
        }

        #endregion

        #region Properties
        /// <summary>
        /// Returns BN_num_bits()
        /// </summary>
        public int Bits {
            get { return NativeMethods.BN_num_bits(ptr); }
        }

        /// <summary>
        /// Converts the result of Bits into the number of bytes.
        /// </summary>
        public int Bytes {
            get { return (Bits + 7) / 8; }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Calls BN_clear()
        /// </summary>
        public void Clear()
        {
            NativeMethods.BN_clear(ptr);
        }

        /// <summary>
        /// Calls BN_rand_range()
        /// </summary>
        /// <param name="range"></param>
        /// <returns></returns>
        public static BigNumber NextRange(BigNumber range)
        {
            BigNumber bn = new BigNumber();
            NativeMethods.ExpectSuccess(NativeMethods.BN_rand_range(bn.Handle, range.Handle));
            return bn;
        }

        /// <summary>
        /// Calls BN_pseudo_rand()
        /// </summary>
        /// <param name="bits"></param>
        /// <param name="top"></param>
        /// <param name="bottom"></param>
        /// <returns></returns>
        public static BigNumber PseudoNext(int bits, int top, int bottom)
        {
            var bn = new BigNumber();
            NativeMethods.ExpectSuccess(NativeMethods.BN_pseudo_rand(bn.Handle, bits, top, bottom));

            return bn;
        }

        /// <summary>
        /// Calls BN_pseudo_rand_range()
        /// </summary>
        /// <param name="range"></param>
        /// <returns></returns>
        public static BigNumber PseudoNextRange(BigNumber range)
        {
            var bn = new BigNumber();
            NativeMethods.ExpectSuccess(NativeMethods.BN_pseudo_rand_range(bn.Handle, range.Handle));

            return bn;
        }
        #endregion

        #region Operators
        /// <summary>
        /// Calls BN_add()
        /// </summary>
        /// <param name="lhs"></param>
        /// <param name="rhs"></param>
        /// <returns></returns>
        public static BigNumber operator +(BigNumber lhs, BigNumber rhs)
        {
            var ret = new BigNumber();
            NativeMethods.ExpectSuccess(NativeMethods.BN_add(ret.Handle, lhs.Handle, rhs.Handle));

            return ret;
        }

        /// <summary>
        /// Calls BN_sub()
        /// </summary>
        /// <param name="lhs"></param>
        /// <param name="rhs"></param>
        /// <returns></returns>
        public static BigNumber operator -(BigNumber lhs, BigNumber rhs)
        {
            var ret = new BigNumber();
            NativeMethods.ExpectSuccess(NativeMethods.BN_sub(ret.Handle, lhs.Handle, rhs.Handle));

            return ret;
        }

        /// <summary>
        /// Determines if lhs is by-value equal to rhs
        /// </summary>
        /// <param name="lhs"></param>
        /// <param name="rhs"></param>
        /// <returns></returns>
        public static bool operator ==(BigNumber lhs, BigNumber rhs)
        {
            if (ReferenceEquals(lhs, rhs))
                return true;
            if ((object)lhs == null || (object)rhs == null)
                return false;

            return lhs.Equals(rhs);
        }

        /// <summary>
        /// Determines if lhs is by-value different than rhs
        /// </summary>
        /// <param name="lhs"></param>
        /// <param name="rhs"></param>
        /// <returns></returns>
        public static bool operator !=(BigNumber lhs, BigNumber rhs)
        {
            return !(lhs == rhs);
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Calls BN_cmp()
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            var rhs = obj as BigNumber;
            if ((object)rhs == null)
                return false;

            return NativeMethods.BN_cmp(ptr, rhs.ptr) == 0;
        }

        /// <summary>
        /// Creates a hash code by converting this object to a decimal string and
        /// returns the hash code of that string.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return ToDecimalString().GetHashCode();
        }

        /// <summary>
        /// Calls BN_print()
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.BN_print(bio.Handle, ptr));
        }
        #endregion

        #region IDisposable Members

        /// <summary>
        /// Calls BN_free()
        /// </summary>
        protected override void OnDispose()
        {
            NativeMethods.BN_free(ptr);
        }

        #endregion

        #region IComparable<BigNumber> Members

        /// <summary>
        /// Calls BN_cmp()
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public int CompareTo(BigNumber other)
        {
            return NativeMethods.BN_cmp(ptr, other.ptr);
        }

        #endregion

        #region Callbacks

        /// <summary>
        /// Generator callback. Used mostly for status indications for long-
        /// running generator functions.
        /// </summary>
        /// <param name="p"></param>
        /// <param name="n"></param>
        /// <param name="arg"></param>
        /// <returns></returns>
        public delegate int GeneratorHandler(int p, int n, object arg);

        internal class GeneratorThunk
        {
            private NativeMethods.bn_gencb_st gencb = new NativeMethods.bn_gencb_st();
            private GeneratorHandler OnGenerator;
            private object arg;

            public NativeMethods.bn_gencb_st CallbackStruct {
                get { return gencb; }
            }

            public GeneratorThunk(GeneratorHandler client, object arg)
            {
                OnGenerator = client;
                this.arg = arg;

                gencb.ver = 2;
                gencb.arg = IntPtr.Zero;
                gencb.cb = OnGeneratorThunk;
            }

            internal int OnGeneratorThunk(int p, int n, IntPtr arg)
            {
                if (OnGenerator != null) {
                    try {
                        return OnGenerator(p, n, this.arg);
                    } catch (Exception) {
                        return 0;
                    }
                } else {
                    // return 1 to allow generation to succeed with
                    // no user callback
                    return 1;
                }
            }
        }

        #endregion

        #region Context
        /// <summary>
        /// Wraps BN_CTX
        /// </summary>
        public class Context : Base
        {
            /// <summary>
            /// Calls BN_CTX_new()
            /// </summary>
            public Context()
                : base(NativeMethods.ExpectNonNull(NativeMethods.BN_CTX_new()), true)
            {
            }

            /// <summary>
            /// Returns BN_CTX_get()
            /// </summary>
            public BigNumber BigNumber {
                get { return new BigNumber(NativeMethods.ExpectNonNull(NativeMethods.BN_CTX_get(ptr)), false); }
            }

            /// <summary>
            /// Calls BN_CTX_start()
            /// </summary>
            public void Start()
            {
                NativeMethods.BN_CTX_start(ptr);
            }

            /// <summary>
            /// Calls BN_CTX_end()
            /// </summary>
            public void End()
            {
                NativeMethods.BN_CTX_end(ptr);
            }

            /// <summary>
            /// Calls BN_CTX_free()
            /// </summary>
            protected override void OnDispose()
            {
                NativeMethods.BN_CTX_free(ptr);
            }
        }
        #endregion
    }
}
