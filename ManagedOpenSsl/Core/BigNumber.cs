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
        public static readonly BigNumber One = new BigNumber(NativeMethods.BN_value_one(), false);

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
            : base(NativeMethods.BN_dup(rhs.Handle), true)
        {
        }

        /// <summary>
        /// Creates a BigNumber by calling BN_set_word()
        /// </summary>
        /// <param name="value"></param>
        public BigNumber(uint value)
            : this()
        {
            NativeMethods.ExpectSuccess(NativeMethods.BN_set_word(Handle, value));
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
            return NativeMethods.PtrToStringAnsi(NativeMethods.BN_bn2dec(Handle), true);
        }

        /// <summary>
        /// Calls BN_bn2hex()
        /// </summary>
        /// <returns></returns>
        public string ToHexString()
        {
            return NativeMethods.PtrToStringAnsi(NativeMethods.BN_bn2hex(Handle), true);
        }

        /// <summary>
        /// Calls BN_get_word()
        /// </summary>
        /// <param name="rhs"></param>
        /// <returns></returns>
        public static implicit operator uint(BigNumber rhs)
        {
            return NativeMethods.BN_get_word(rhs.Handle);
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
            NativeMethods.ExpectSuccess(NativeMethods.BN_bn2bin(rhs.Handle, bytes));

            return bytes;
        }

        /// <summary>
        /// Calls BN_bn2bin()
        /// </summary>
        /// <param name="bytes"></param>
        public void ToBytes(byte[] bytes)
        {
            NativeMethods.ExpectSuccess(NativeMethods.BN_bn2bin(Handle, bytes));
        }

        #endregion

        #region Properties
        /// <summary>
        /// Returns BN_num_bits()
        /// </summary>
        public int Bits {
            get { return NativeMethods.BN_num_bits(Handle); }
        }

        /// <summary>
        /// Converts the result of Bits into the number of bytes.
        /// </summary>
        public int Bytes {
            get { return (Bits + 7) / 8; }
        }

        public bool IsZero {
            get { return Convert.ToBoolean(NativeMethods.BN_is_zero(Handle)); }
        }

        public bool IsOne {
            get { return Convert.ToBoolean(NativeMethods.BN_is_one(Handle)); }
        }

        public bool IsOdd {
            get { return Convert.ToBoolean(NativeMethods.BN_is_odd(Handle)); }
        }

        public bool IsNegative {
            get { return Convert.ToBoolean(NativeMethods.BN_is_negative(Handle)); }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Calls BN_clear()
        /// </summary>
        public void Clear()
        {
            NativeMethods.BN_clear(Handle);
        }

        public void CopyTo(BigNumber to)
        {
            NativeMethods.ExpectNonNull(NativeMethods.BN_copy(to.Handle, Handle));
        }

        public static void Swap(BigNumber a, BigNumber b)
        {
            NativeMethods.BN_swap(a.Handle, b.Handle);
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

        public static BigNumber Generate(int bits, bool safe, GeneratorCallback callback = null)
        {
            return Generate(bits, safe, null, null, callback);
        }

        public static BigNumber Generate(int bits, bool safe, BigNumber add, BigNumber rem, GeneratorCallback callback = null)
        {
            IntPtr addptr = (add != null ? add.Handle : IntPtr.Zero);
            IntPtr remptr = (rem != null ? rem.Handle : IntPtr.Zero);
            IntPtr cbptr = (callback != null ? callback.Handle : IntPtr.Zero);
            BigNumber ret = new BigNumber();
            NativeMethods.ExpectSuccess(
                NativeMethods.BN_generate_prime_ex(ret.Handle, bits, (safe ? 1 : 0), addptr, remptr, cbptr)
            );
            return ret;
        }

        /// <summary>
        /// Test if this instance is a prime number by performing a Miller-Rabin test.
        /// </summary>
        /// <param name="ncheck">Specify the iterations, 0 to automatic select by OpenSSL</param>
        /// <param name="callback">Callback function</param>
        /// <returns></returns>
        public bool IsPrime(int ncheck = 0, GeneratorCallback callback = null)
        {
            IntPtr cbptr = (callback != null ? callback.Handle : IntPtr.Zero);
            int ret = NativeMethods.BN_is_prime_ex(Handle, ncheck, IntPtr.Zero, cbptr);
            if (ret < 0) {
                throw new OpenSslException();
            }
            return (ret == 0 ? false : true);
        }

        public BigNumber Sqrt()
        {
            var ret = new BigNumber();
            using (Context ctx = new Context()) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_sqr(ret.Handle, Handle, ctx.Handle));
            }
            return ret;
        }

        public BigNumber Gcd(BigNumber b)
        {
            var ret = new BigNumber();
            using (Context ctx = new Context()) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_gcd(ret.Handle, Handle, b.Handle, ctx.Handle));
            }
            return ret;
        }

        public BigNumber NNMod(BigNumber m)
        {
            var ret = new BigNumber();
            using (Context ctx = new Context()) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_nnmod(ret.Handle, Handle, m.Handle, ctx.Handle));
            }
            return ret;
        }

        public BigNumber ModAdd(BigNumber b, BigNumber m)
        {
            var ret = new BigNumber();
            using (Context ctx = new Context()) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_mod_add(ret.Handle, Handle, b.Handle, m.Handle, ctx.Handle));
            }
            return ret;
        }

        public BigNumber ModSub(BigNumber b, BigNumber m)
        {
            var ret = new BigNumber();
            using (Context ctx = new Context()) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_mod_sub(ret.Handle, Handle, b.Handle, m.Handle, ctx.Handle));
            }
            return ret;
        }

        public BigNumber ModMul(BigNumber b, BigNumber m)
        {
            var ret = new BigNumber();
            using (Context ctx = new Context()) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_mod_mul(ret.Handle, Handle, b.Handle, m.Handle, ctx.Handle));
            }
            return ret;
        }

        public BigNumber ModSqrt(BigNumber m)
        {
            var ret = new BigNumber();
            using (Context ctx = new Context()) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_mod_sqr(ret.Handle, Handle, m.Handle, ctx.Handle));
            }
            return ret;
        }

        public BigNumber ModExp(BigNumber p, BigNumber m)
        {
            var ret = new BigNumber();
            using (Context ctx = new Context()) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_mod_exp(ret.Handle, Handle, p.Handle, m.Handle, ctx.Handle));
            }
            return ret;
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

        public static BigNumber operator +(BigNumber lhs, uint rhs)
        {
            var ret = new BigNumber(lhs);
            NativeMethods.ExpectSuccess(NativeMethods.BN_add_word(ret.Handle, rhs));
            return ret;
        }

        public static BigNumber operator +(BigNumber lhs, int rhs)
        {
            var ret = new BigNumber(lhs);
            if (rhs >= 0) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_add_word(ret.Handle, (uint)rhs));
            } else {
                NativeMethods.ExpectSuccess(NativeMethods.BN_sub_word(ret.Handle, (uint)Math.Abs(rhs)));
            }
            return ret;
        }

        public static BigNumber operator ++(BigNumber lhs)
        {
            var ret = new BigNumber(lhs);
            NativeMethods.ExpectSuccess(NativeMethods.BN_add_word(ret.Handle, 1));
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

        public static BigNumber operator -(BigNumber lhs, uint rhs)
        {
            var ret = new BigNumber(lhs);
            NativeMethods.ExpectSuccess(NativeMethods.BN_sub_word(ret.Handle, rhs));
            return ret;
        }

        public static BigNumber operator -(BigNumber lhs, int rhs)
        {
            var ret = new BigNumber(lhs);
            if (rhs >= 0) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_sub_word(ret.Handle, (uint)rhs));
            } else {
                NativeMethods.ExpectSuccess(NativeMethods.BN_add_word(ret.Handle, (uint)Math.Abs(rhs)));
            }
            return ret;
        }

        public static BigNumber operator --(BigNumber lhs)
        {
            var ret = new BigNumber(lhs);
            NativeMethods.ExpectSuccess(NativeMethods.BN_sub_word(ret.Handle, 1));
            return ret;
        }

        public static BigNumber operator *(BigNumber lhs, BigNumber rhs)
        {
            using (Context ctx = new Context()) {
                BigNumber ret = new BigNumber();
                NativeMethods.ExpectSuccess(NativeMethods.BN_mul(ret.Handle, lhs.Handle, rhs.Handle, ctx.Handle));
                return ret;
            }
        }

        public static BigNumber operator *(BigNumber lhs, uint rhs)
        {
            var ret = new BigNumber(lhs);
            NativeMethods.ExpectSuccess(NativeMethods.BN_mul_word(ret.Handle, rhs));
            return ret;
        }

        public static BigNumber operator /(BigNumber lhs, BigNumber rhs)
        {
            using (Context ctx = new Context()) {
                BigNumber ret = new BigNumber();
                NativeMethods.ExpectSuccess(NativeMethods.BN_div(ret.Handle, IntPtr.Zero, lhs.Handle, rhs.Handle, ctx.Handle));
                return ret;
            }
        }

        public static uint operator /(BigNumber lhs, uint rhs)
        {
            var ret = NativeMethods.BN_div_word(lhs.Handle, rhs);
            if (unchecked((int)ret) == -1) {
                throw new OpenSslException();
            }
            return ret;
        }

        public static BigNumber operator %(BigNumber lhs, BigNumber rhs)
        {
            using (Context ctx = new Context()) {
                BigNumber ret = new BigNumber();
                NativeMethods.ExpectSuccess(NativeMethods.BN_div(IntPtr.Zero, ret.Handle, lhs.Handle, rhs.Handle, ctx.Handle));
                return ret;
            }
        }

        public static uint operator %(BigNumber lhs, uint rhs)
        {
            var ret = NativeMethods.BN_mod_word(lhs.Handle, rhs);
            if (unchecked((int)ret) == -1) {
                throw new OpenSslException();
            }
            return ret;
        }

        public static BigNumber operator ^(BigNumber lhs, BigNumber rhs)
        {
            using (Context ctx = new Context()) {
                BigNumber ret = new BigNumber();
                NativeMethods.ExpectSuccess(NativeMethods.BN_exp(ret.Handle, lhs.Handle, rhs.Handle, ctx.Handle));
                return ret;
            }
        }

        public static BigNumber operator <<(BigNumber lhs, int rhs)
        {
            BigNumber ret = new BigNumber();
            if (rhs == 1) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_lshift1(ret.Handle, lhs.Handle));
            } else {
                NativeMethods.ExpectSuccess(NativeMethods.BN_lshift(ret.Handle, lhs.Handle, rhs));
            }
            return ret;
        }

        public static BigNumber operator >>(BigNumber lhs, int rhs)
        {
            BigNumber ret = new BigNumber();
            if (rhs == 1) {
                NativeMethods.ExpectSuccess(NativeMethods.BN_rshift1(ret.Handle, lhs.Handle));
            } else {
                NativeMethods.ExpectSuccess(NativeMethods.BN_rshift(ret.Handle, lhs.Handle, rhs));
            }
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

        public static bool operator <(BigNumber lhs, BigNumber rhs)
        {
            return lhs.CompareTo(rhs) == -1;
        }

        public static bool operator <=(BigNumber lhs, BigNumber rhs)
        {
            return lhs.CompareTo(rhs) != 1;
        }

        public static bool operator >(BigNumber lhs, BigNumber rhs)
        {
            return lhs.CompareTo(rhs) == 1;
        }

        public static bool operator >=(BigNumber lhs, BigNumber rhs)
        {
            return lhs.CompareTo(rhs) != -1;
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

            return NativeMethods.BN_cmp(Handle, rhs.Handle) == 0;
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
            NativeMethods.ExpectSuccess(NativeMethods.BN_print(bio.Handle, Handle));
        }
        #endregion

        #region IDisposable Members

        /// <summary>
        /// Calls BN_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.BN_free(Handle);
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
            return NativeMethods.BN_cmp(Handle, other.Handle);
        }

        #endregion

        #region Callbacks

        /// <summary>
        /// Generator callback. Used mostly for status indications for long-
        /// running generator functions.
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <param name="cb"></param>
        /// <returns></returns>
        public delegate int GeneratorHandler(int a, int b, GeneratorCallback cb);

        public class GeneratorCallback : Base
        {
            private NativeMethods.GeneratorHandler native_callback; //Hold the delegate
            private GeneratorHandler callback;
            private object arg;

            public GeneratorCallback() : this(null, null)
            {

            }

            public GeneratorCallback(GeneratorHandler handler, object arg) : base(NativeMethods.ExpectNonNull(NativeMethods.BN_GENCB_new()), true)
            {
                callback = handler;
                this.arg = arg;
                native_callback = new NativeMethods.GeneratorHandler(OnGeneratorThunk);
                NativeMethods.BN_GENCB_set(Handle, native_callback, IntPtr.Zero);
            }

            public void SetCallback(GeneratorHandler handler)
            {
                callback = handler;
            }

            private int OnGeneratorThunk(int a, int b, IntPtr arg)
            {
                if (callback != null) {
                    try {
                        return callback(a, b, this);
                    } catch (Exception) {
                        return 0;
                    }
                } else {
                    // return 1 to allow generation to succeed with
                    // no user callback
                    return 1;
                }
            }

            public object Argument {
                get {
                    return arg;
                }
                set {
                    arg = value;
                }
            }

            protected override void ReleaseHandle()
            {
                NativeMethods.BN_GENCB_free(Handle);
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
                get { return new BigNumber(NativeMethods.ExpectNonNull(NativeMethods.BN_CTX_get(Handle)), false); }
            }

            /// <summary>
            /// Calls BN_CTX_start()
            /// </summary>
            public void Start()
            {
                NativeMethods.BN_CTX_start(Handle);
            }

            /// <summary>
            /// Calls BN_CTX_end()
            /// </summary>
            public void End()
            {
                NativeMethods.BN_CTX_end(Handle);
            }

            /// <summary>
            /// Calls BN_CTX_free()
            /// </summary>
            protected override void ReleaseHandle()
            {
                NativeMethods.BN_CTX_free(Handle);
            }
        }
        #endregion
    }
}
