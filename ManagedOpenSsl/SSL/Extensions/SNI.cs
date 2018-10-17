using OpenSSL.Core;
using OpenSSL.Native;
using OpenSSL.SSL;
using System;
using System.Runtime.InteropServices;

namespace OpenSSL.Extensions
{
    /// <summary>
    /// Sni callback.
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int SniCallback(IntPtr ssl, IntPtr ad, IntPtr arg);

    internal class Sni
    {
        internal const int TLSEXT_NAMETYPE_host_name = 0;

        private readonly string _serverName;
        private static IntPtr _serverNamePtr;

        public Sni(string serverName)
        {
            _serverName = serverName;
            _serverNamePtr = Marshal.StringToHGlobalAnsi(serverName);
        }

        public string ServerName { get { return _serverName; } }


        public void AttachSniExtensionClient(IntPtr ssl, IntPtr sslCtx, SniCallback cb)
        {
            SSL_CTX_set_tlsext_servername_callback(cb, sslCtx);

            NativeMethods.SSL_CTX_ctrl(sslCtx, SSL_Ctrl.SET_TLSEXT_SERVERNAME_ARG, 0, _serverNamePtr);
            SSL_set_tlsext_host_name(ssl);
        }

        public void AttachSniExtensionServer(IntPtr ssl, IntPtr sslCtx, SniCallback cb)
        {
            SSL_CTX_set_tlsext_servername_callback(cb, sslCtx);
            //SSL_CTX_ctrl(sslCtx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, serverNamePtr);
        }

        private static int SSL_session_reused(IntPtr ssl)
        {
            return NativeMethods.SSL_session_reused(ssl);
        }

        private int SSL_set_tlsext_host_name(IntPtr s)
        {
            return NativeMethods.SSL_ctrl(s, SSL_Ctrl.SET_TLSEXT_HOSTNAME,
                TLSEXT_NAMETYPE_host_name,
                _serverNamePtr);
        }

        private int SSL_CTX_set_tlsext_servername_callback(SniCallback cb, IntPtr ctx)
        {
            var cbPtr = Marshal.GetFunctionPointerForDelegate(cb);
            return NativeMethods.SSL_CTX_callback_ctrl(ctx, SSL_Ctrl.SET_TLSEXT_SERVERNAME_CB, cbPtr);
        }

        //This callback just checks was session reused or not.
        //If we renegotiate each time we make a connection then clientSniArgAck
        //should be true
        public int ClientSniCb(IntPtr ssl, IntPtr ad, IntPtr arg)
        {
            var hnptr = NativeMethods.SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

            if (NativeMethods.SSL_get_servername_type(ssl) != -1) {
                var isReused = SSL_session_reused(ssl) != 0;
                var clientSniArgAck = !isReused && hnptr != IntPtr.Zero;
#if DEBUG
                Console.WriteLine("Servername ack is {0}", clientSniArgAck);
#endif
            } else {
#if DEBUG
                Console.WriteLine("Can't use SSL_get_servername");
#endif
                throw new Exception("Cant use servername extension");
            }

            return (int)Errors.SSL_TLSEXT_ERR_OK;
        }

        public int ServerSniCb(IntPtr ssl, IntPtr ad, IntPtr arg)
        {
            //Hostname in TLS extension
            var extServerNamePtr = NativeMethods.SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
            var extServerName = Marshal.PtrToStringAnsi(extServerNamePtr);

            if (!_serverName.Equals(extServerName)) {
#if DEBUG
                Console.WriteLine("Server names are not equal");
#endif
                throw new Exception("Server names are not equal");
            }

            return (int)Errors.SSL_TLSEXT_ERR_OK;
        }

        ~Sni()
        {
            //Marshal.FreeHGlobal(_serverNamePtr);
        }
    }
}
