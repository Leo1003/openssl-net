using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OPENSSL_init_ssl(OpenSSL_Init opts, IntPtr settings);

        #region SSL Methods

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr TLS_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr TLS_server_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr TLS_client_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DTLS_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DTLS_client_method();

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DTLS_server_method();

        #endregion

        #region SSL_CTX

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CTX_new(IntPtr sslMethod);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_free(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_ctrl(IntPtr ctx, SSLCtrl cmd, int arg, IntPtr parg);

        /// <summary>
        /// #define SSL_CTX_clear_mode in ssl.h - calls SSL_CTX_ctrl()
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="op"></param>
        /// <returns></returns>
        public static SSL_Mode SSL_CTX_clear_mode(IntPtr ctx, SSL_Mode op)
        {
            return (SSL_Mode)SSL_CTX_ctrl(ctx, SSLCtrl.CLEAR_MODE, unchecked((int)op), IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_ctrl in ssl.h - calls SSL_CTX_ctrl()
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="op"></param>
        /// <returns></returns>
        public static SSL_Mode SSL_CTX_set_mode(IntPtr ctx, SSL_Mode op)
        {
            return (SSL_Mode)SSL_CTX_ctrl(ctx, SSLCtrl.MODE, unchecked((int)op), IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_get_mode in ssl.h - calls SSL_CTX_ctrl
        /// </summary>
        /// <param name="ctx"></param>
        /// <returns></returns>
        public static SSL_Mode SSL_CTX_get_mode(IntPtr ctx)
        {
            return (SSL_Mode)SSL_CTX_ctrl(ctx, SSLCtrl.MODE, 0, IntPtr.Zero);
        }

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static SSL_Options SSL_CTX_get_options(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static SSL_Options SSL_CTX_set_options(IntPtr ctx, SSL_Options op);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static SSL_Options SSL_CTX_clear_options(IntPtr ctx, SSL_Options op);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_cert_store(IntPtr ctx, IntPtr cert_store);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_verify(IntPtr ctx, SSL_Verify mode, VerifyCertCallback callback);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_verify_depth(IntPtr ctx, int depth);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_client_CA_list(IntPtr ctx, IntPtr name_list);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CTX_get_client_CA_list(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_load_verify_locations(IntPtr ctx, string file, string path);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_set_default_verify_paths(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_set_cipher_list(IntPtr ctx, string cipher_string);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_certificate_chain_file(IntPtr ctx, string file);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_certificate(IntPtr ctx, IntPtr cert);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_PrivateKey(IntPtr ctx, IntPtr pkey);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_use_PrivateKey_file(IntPtr ctx, string file, int type);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_check_private_key(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CTX_set_session_id_context(IntPtr ctx, byte[] sid_ctx, uint sid_ctx_len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_default_passwd_cb_userdata(IntPtr ssl, IntPtr data);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_default_passwd_cb(IntPtr ssl, pem_password_cb callback);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_client_cert_cb(IntPtr ssl_ctx, client_cert_cb callback);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_CTX_callback_ctrl(IntPtr ctx, SSLCtrl cmd, IntPtr cb);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_CTX_set_alpn_protos(IntPtr ctx, byte[] protos, UInt32 protos_len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_CTX_set_alpn_select_cb(IntPtr ctx, alpn_cb alpnCb, IntPtr arg);

        #endregion

        #region SSL

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static string SSL_CIPHER_description(IntPtr ssl_cipher, byte[] buf, int buf_len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CIPHER_get_name(IntPtr ssl_cipher);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_CIPHER_get_bits(IntPtr ssl_cipher, out int alg_bits);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_CIPHER_get_version(IntPtr ssl_cipher);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_current_cipher(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_ciphers(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_get_verify_result(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_set_verify_result(IntPtr ssl, int v);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_peer_certificate(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_get_error(IntPtr ssl, int ret_code);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_accept(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_shutdown(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_write(IntPtr ssl, byte[] buf, int len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_read(IntPtr ssl, byte[] buf, int len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_renegotiate(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_set_session_id_context(IntPtr ssl, byte[] sid_ctx, uint sid_ctx_len);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_do_handshake(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_connect_state(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_accept_state(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_connect(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_new(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_free(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static OpenSSL_HandshakeState SSL_get_state(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_bio(IntPtr ssl, IntPtr read_bio, IntPtr write_bio);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_use_certificate_file(IntPtr ssl, string file, int type);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_use_PrivateKey_file(IntPtr ssl, string file, int type);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_clear(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_load_client_CA_file(string file);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_client_CA_list(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_set_client_CA_list(IntPtr ssl, IntPtr name_list);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr SSL_get_certificate(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_use_certificate(IntPtr ssl, IntPtr x509);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int SSL_use_PrivateKey(IntPtr ssl, IntPtr evp_pkey);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_ctrl(IntPtr ssl, SSLCtrl cmd, int larg, IntPtr parg);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_session_reused(IntPtr ssl);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SSL_get_servername(IntPtr s, int type);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SSL_get_servername_type(IntPtr s);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SSL_get_session(IntPtr s);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SSL_get0_alpn_selected(IntPtr ssl, out IntPtr data, out int len);

        #endregion
    }
}
