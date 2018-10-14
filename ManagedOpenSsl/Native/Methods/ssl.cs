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
        /// #define SSL_CTX_ctrl in ssl.h - calls SSL_CTX_ctrl()
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="op"></param>
        /// <returns></returns>
        public static int SSL_CTX_set_mode(IntPtr ctx, int op)
        {
            return SSL_CTX_ctrl(ctx, SSLCtrl.MODE, op, IntPtr.Zero);
        }

        /// <summary>
        /// #define SSL_CTX_get_mode in ssl.h - calls SSL_CTX_ctrl
        /// </summary>
        /// <param name="ctx"></param>
        /// <returns></returns>
        public static int SSL_CTX_get_mode(IntPtr ctx)
        {
            return SSL_CTX_ctrl(ctx, SSLCtrl.MODE, 0, IntPtr.Zero);
        }

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint SSL_CTX_get_options(IntPtr ctx);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint SSL_CTX_set_options(IntPtr ctx, int op);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static uint SSL_CTX_clear_options(IntPtr ctx, int op);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_cert_store(IntPtr ctx, IntPtr cert_store);

        [DllImport(SSLDLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void SSL_CTX_set_verify(IntPtr ctx, int mode, VerifyCertCallback callback);

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

        #endregion
    }
}
