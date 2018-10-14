using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_get_builtin_curves(IntPtr r, int nitems);

        #region EC_METHOD

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GFp_simple_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GFp_mont_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GFp_nist_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GF2m_simple_method();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_METHOD_get_field_type(IntPtr meth);

        #endregion

        #region EC_GROUP

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_new(IntPtr meth);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_free(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_clear_free(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_copy(IntPtr dst, IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_dup(IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_method_of(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_set_generator(IntPtr group, IntPtr generator, IntPtr order, IntPtr cofactor);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_get0_generator(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_order(IntPtr group, IntPtr order, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_cofactor(IntPtr group, IntPtr cofactor, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_set_curve_name(IntPtr group, int nid);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_curve_name(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_set_asn1_flag(IntPtr group, int flag);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_asn1_flag(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_GROUP_set_point_conversion_form(IntPtr x, int y);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_point_conversion_form(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static byte[] EC_GROUP_get0_seed(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_seed_len(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_set_seed(IntPtr x, byte[] buf, int len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_set_curve(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_curve(IntPtr group, IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_get_degree(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_check(IntPtr group, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_check_discriminant(IntPtr group, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_cmp(IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_new_curve_GFp(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_new_curve_GF2m(IntPtr p, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_GROUP_new_by_curve_name(int nid);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_precompute_mult(IntPtr group, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_GROUP_have_precompute_mult(IntPtr group);

        #endregion

        #region EC_POINT

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_new(IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_POINT_free(IntPtr point);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_POINT_clear_free(IntPtr point);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_copy(IntPtr dst, IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_dup(IntPtr src, IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_method_of(IntPtr point);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_set_to_infinity(IntPtr group, IntPtr point);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_set_Jprojective_coordinates_GFp(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            IntPtr y,
            IntPtr z,
            IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_get_Jprojective_coordinates_GFp(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            IntPtr y,
            IntPtr z,
            IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_set_affine_coordinates(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_get_affine_coordinates(IntPtr group, IntPtr p, IntPtr x, IntPtr y, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_set_compressed_coordinates(
            IntPtr group,
            IntPtr p,
            IntPtr x,
            int y_bit,
            IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_point2oct(IntPtr group, IntPtr p, int form, byte[] buf, int len, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_oct2point(IntPtr group, IntPtr p, byte[] buf, int len, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_point2bn(IntPtr a, IntPtr b, int form, IntPtr c, IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_bn2point(IntPtr a, IntPtr b, IntPtr c, IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static string EC_POINT_point2hex(IntPtr a, IntPtr b, int form, IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_POINT_hex2point(IntPtr a, string s, IntPtr b, IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_add(IntPtr group, IntPtr r, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_dbl(IntPtr group, IntPtr r, IntPtr a, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_invert(IntPtr group, IntPtr a, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_is_at_infinity(IntPtr group, IntPtr p);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_is_on_curve(IntPtr group, IntPtr point, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_cmp(IntPtr group, IntPtr a, IntPtr b, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_make_affine(IntPtr a, IntPtr b, IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINTs_make_affine(IntPtr a, int num, IntPtr[] b, IntPtr c);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINTs_mul(IntPtr group, IntPtr r, IntPtr n, int num, IntPtr[] p, IntPtr[] m, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_POINT_mul(IntPtr group, IntPtr r, IntPtr n, IntPtr q, IntPtr m, IntPtr ctx);

        #endregion

        #region EC_KEY

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr EC_KEY_dup_func(IntPtr x);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void EC_KEY_free_func(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_new_by_curve_name(int nid);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_KEY_free(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_copy(IntPtr dst, IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_dup(IntPtr src);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_up_ref(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_get0_group(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_set_group(IntPtr key, IntPtr group);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_get0_private_key(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_set_private_key(IntPtr key, IntPtr prv);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EC_KEY_get0_public_key(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_set_public_key(IntPtr key, IntPtr pub);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint EC_KEY_get_enc_flags(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_KEY_set_enc_flags(IntPtr x, uint y);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_get_conv_form(IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_KEY_set_conv_form(IntPtr x, int y);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EC_KEY_set_asn1_flag(IntPtr x, int y);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_precompute_mult(IntPtr key, IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_generate_key(IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EC_KEY_check_key(IntPtr key);

        #endregion

        #region ECDSA

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ECDSA_SIG_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void ECDSA_SIG_free(IntPtr sig);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int i2d_ECDSA_SIG(IntPtr sig, byte[] pp);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr d2i_ECDSA_SIG(IntPtr sig, byte[] pp, long len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ECDSA_do_sign(byte[] dgst, int dgst_len, IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr ECDSA_do_sign_ex(byte[] dgst, int dgstlen, IntPtr kinv, IntPtr rp, IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_do_verify(byte[] dgst, int dgst_len, IntPtr sig, IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_size(IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_sign_setup(IntPtr eckey, IntPtr ctx, IntPtr kinv, IntPtr rp);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_sign(int type, byte[] dgst, int dgstlen, byte[] sig, ref uint siglen, IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_sign_ex(
            int type,
            byte[] dgst,
            int dgstlen,
            byte[] sig,
            ref uint siglen,
            IntPtr kinv,
            IntPtr rp,
            IntPtr eckey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDSA_verify(int type, byte[] dgst, int dgstlen, byte[] sig, int siglen, IntPtr eckey);

        #endregion

        #region ECDH
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr ECDH_KDF([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pin,
                                        int inlen,
                                        IntPtr pout,
                                        ref int outlen);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int ECDH_compute_key(byte[] pout, int outlen, IntPtr pub_key, IntPtr ecdh, ECDH_KDF kdf);
        #endregion
    }
}
