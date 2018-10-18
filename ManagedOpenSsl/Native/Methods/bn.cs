using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_options();


        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_CTX_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_CTX_free(IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_CTX_start(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_CTX_get(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_CTX_end(IntPtr ctx);


        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_value_one();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_free(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_clear_free(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_bin2bn(byte[] s, int len, IntPtr ret);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_bn2bin(IntPtr a, byte[] to);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_clear(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_dup(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_copy(IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_swap(IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_cmp(IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_ucmp(IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_sub(IntPtr r, IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_usub(IntPtr r, IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_uadd(IntPtr r, IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_add(IntPtr r, IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mul(IntPtr r, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_sqr(IntPtr r, IntPtr a, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_lshift(IntPtr r, IntPtr a, int n);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_lshift1(IntPtr r, IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_rshift(IntPtr r, IntPtr a, int n);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_rshift1(IntPtr r, IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_num_bits(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_num_bits_word(uint l);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_div(IntPtr dv, IntPtr rem, IntPtr a, IntPtr d, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_nnmod(IntPtr r, IntPtr m, IntPtr d, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_add(IntPtr r, IntPtr a, IntPtr b, IntPtr m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_add_quick(IntPtr r, IntPtr a, IntPtr b, IntPtr m);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_sub(IntPtr r, IntPtr a, IntPtr b, IntPtr m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_sub_quick(IntPtr r, IntPtr a, IntPtr b, IntPtr m);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_mul(IntPtr r, IntPtr a, IntPtr b, IntPtr m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_sqr(IntPtr r, IntPtr a, IntPtr m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_lshift1(IntPtr r, IntPtr a, IntPtr m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_lshift1_quick(IntPtr r, IntPtr a, IntPtr m);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_lshift(IntPtr r, IntPtr a, int n, IntPtr m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_lshift_quick(IntPtr r, IntPtr a, int n, IntPtr m);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_exp(IntPtr r, IntPtr a, IntPtr p, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_exp(IntPtr r, IntPtr a, IntPtr p, IntPtr m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_inverse(IntPtr r, IntPtr a, IntPtr n, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mod_sqrt(IntPtr r, IntPtr a, IntPtr n, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_gcd(IntPtr r, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_print(IntPtr fp, IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_bn2hex(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_bn2dec(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_hex2bn(out IntPtr a, byte[] str);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_dec2bn(out IntPtr a, byte[] str);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint BN_mod_word(IntPtr a, uint w);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint BN_div_word(IntPtr a, uint w);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_mul_word(IntPtr a, uint w);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_add_word(IntPtr a, uint w);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_sub_word(IntPtr a, uint w);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_set_word(IntPtr a, uint w);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint BN_get_word(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_abs_is_word(IntPtr a, uint w);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_is_zero(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_is_one(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_is_word(IntPtr a, uint w);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_is_odd(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_is_negative(IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_set_negative(IntPtr b, int n);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_rand(IntPtr rnd, int bits, int top, int bottom);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_pseudo_rand(IntPtr rnd, int bits, int top, int bottom);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_rand_range(IntPtr rnd, IntPtr range);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_priv_rand_range(IntPtr rnd, IntPtr range);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int BN_pseudo_rand_range(IntPtr rnd, IntPtr range);

        #region BN_GENCB

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int GeneratorHandler(int p, int n, IntPtr arg);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr BN_GENCB_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_GENCB_free(IntPtr cb);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BN_GENCB_set(IntPtr gencb, GeneratorHandler callback, IntPtr cb_arg);

        #endregion
        //TODO: Add generate prime & callback support
    }
}
