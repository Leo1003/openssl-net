using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        #region Constants

        public const int EVP_MAX_MD_SIZE = 64;
        //!!(16+20);
        public const int EVP_MAX_KEY_LENGTH = 64;
        public const int EVP_MAX_IV_LENGTH = 16;
        public const int EVP_MAX_BLOCK_LENGTH = 32;

        #endregion

        #region Message Digests

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_md_null();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_md4();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_md5();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha1();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha224();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha256();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha384();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha512();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha512_224();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha512_256();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha3_224();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha3_256();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha3_384();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha3_512();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_shake128();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_shake256();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_mdc2();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_ripemd160();

        #endregion

        #region Ciphers

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_get_cipherbyname(byte[] name);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_enc_null();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede3();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede3_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_cfb64();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_cfb1();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_cfb8();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede_cfb64();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede3_cfb64();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede3_cfb1();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede3_cfb8();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede3_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_des_ede3_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_desx_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_rc4();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_rc4_40();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_idea_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_idea_cfb64();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_idea_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_idea_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_rc2_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_rc2_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_rc2_40_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_rc2_64_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_rc2_cfb64();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_rc2_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_bf_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_bf_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_bf_cfb64();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_bf_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_cast5_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_cast5_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_cast5_cfb64();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_cast5_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_cfb1();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_cfb8();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_cfb128();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_ctr();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_ccm();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_gcm();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_xts();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_wrap();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_wrap_pad();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_ocb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_cfb1();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_cfb8();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_cfb128();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_ctr();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_ccm();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_gcm();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_wrap();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_wrap_pad();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_ocb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_ecb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_cbc();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_cfb1();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_cfb8();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_cfb128();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_ofb();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_ctr();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_ccm();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_gcm();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_xts();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_wrap();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_wrap_pad();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_ocb();

        #endregion

        #region EVP_PKEY

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_PKEY_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_up_ref(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EVP_PKEY_free(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_cmp(IntPtr a, IntPtr b);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_decrypt(IntPtr ctx, IntPtr output, ref UIntPtr outlen, byte[] input, UIntPtr inlen);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_encrypt(IntPtr ctx, IntPtr output, ref UIntPtr outlen, byte[] input, UIntPtr inlen);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_encrypt_old(byte[] enc_key, byte[] key, int key_len, IntPtr pub_key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_id(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_base_id(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_type(int type);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_bits(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_size(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_assign(IntPtr pkey, int type, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_set1_DSA(IntPtr pkey, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_PKEY_get1_DSA(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_set1_RSA(IntPtr pkey, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_PKEY_get1_RSA(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_set1_EC_KEY(IntPtr pkey, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_PKEY_get1_EC_KEY(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_set1_DH(IntPtr pkey, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_PKEY_get1_DH(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_copy_parameters(IntPtr to, IntPtr from);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_missing_parameters(IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_save_parameters(IntPtr pkey, int mode);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_PKEY_cmp_parameters(IntPtr a, IntPtr b);

        #endregion

        #region EVP_CIPHER

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_nid(IntPtr cipher);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_block_size(IntPtr cipher);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_impl_ctx_size(IntPtr cipher);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_key_length(IntPtr cipher);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_iv_length(IntPtr cipher);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint EVP_CIPHER_flags(IntPtr cipher);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_type(IntPtr ctx);

        #endregion

        #region EVP_CIPHER_CTX

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_CIPHER_CTX_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_CTX_reset(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EVP_CIPHER_CTX_free(IntPtr a);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_CTX_rand_key(IntPtr ctx, byte[] key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_CTX_set_padding(IntPtr x, int padding);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_CTX_set_key_length(IntPtr x, int keylen);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_CTX_ctrl(IntPtr ctx, int type, int arg, IntPtr ptr);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CipherInit_ex(IntPtr ctx, IntPtr type, IntPtr impl, byte[] key, byte[] iv, int enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CipherUpdate(IntPtr ctx, byte[] outb, out int outl, byte[] inb, int inl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CipherFinal_ex(IntPtr ctx, byte[] outm, ref int outl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_OpenInit(IntPtr ctx, IntPtr type, byte[] ek, int ekl, byte[] iv, IntPtr priv);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_OpenFinal(IntPtr ctx, byte[] outb, out int outl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_SealInit(
            IntPtr ctx,
            IntPtr type,
            IntPtr[] ek,
            int[] ekl,
            byte[] iv,
            IntPtr[] pubk,
            int npubk);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_SealFinal(IntPtr ctx, byte[] outb, out int outl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DecryptUpdate(IntPtr ctx, byte[] output, out int outl, byte[] input, int inl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_EncryptInit_ex(IntPtr ctx, IntPtr cipher, IntPtr impl, byte[] key, byte[] iv);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_EncryptUpdate(IntPtr ctx, byte[] output, out int outl, byte[] input, int inl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_BytesToKey(
            IntPtr type,
            IntPtr md,
            byte[] salt,
            byte[] data,
            int datal,
            int count,
            byte[] key,
            byte[] iv);

        #endregion

        #region EVP_MD

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_MD_type(IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_MD_pkey_type(IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_MD_size(IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_MD_block_size(IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint EVP_MD_flags(IntPtr md);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_get_digestbyname(byte[] name);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_MD_CTX_reset(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_MD_CTX_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EVP_MD_CTX_free(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestInit_ex(IntPtr ctx, IntPtr type, IntPtr impl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestUpdate(IntPtr ctx, byte[] d, UIntPtr cnt);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestFinal_ex(IntPtr ctx, byte[] md, ref uint s);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_Digest(byte[] data, UIntPtr count, byte[] md, ref uint size, IntPtr type, IntPtr impl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_SignFinal(IntPtr ctx, byte[] md, ref uint s, IntPtr pkey);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_VerifyFinal(IntPtr ctx, byte[] sigbuf, uint siglen, IntPtr pkey);

        #endregion
    }
}
