﻿using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    public enum BIO_Ctrl : int
    {
        RESET = 1,
        EOF = 2,
        INFO = 3,
        SET = 4,
        GET = 5,
        PUSH = 6,
        POP = 7,
        GET_CLOSE = 8,
        SET_CLOSE = 9,
        PENDING = 10,
        FLUSH = 11,
        DUP = 12,
        WPENDING = 13,
        SET_CALLBACK = 14,
        GET_CALLBACK = 15,

        PEEK = 29,
        SET_FILENAME = 30,
        /* dgram BIO stuff */
        DGRAM_CONNECT = 31,
        DGRAM_SET_CONNECTED = 32,
        DGRAM_SET_RECV_TIMEOUT = 33,
        DGRAM_GET_RECV_TIMEOUT = 34,
        DGRAM_SET_SEND_TIMEOUT = 35,
        DGRAM_GET_SEND_TIMEOUT = 36,
        DGRAM_GET_RECV_TIMER_EXP = 37,
        DGRAM_GET_SEND_TIMER_EXP = 38,
        DGRAM_MTU_DISCOVER = 39,
        DGRAM_QUERY_MTU = 40,
        DGRAM_GET_FALLBACK_MTU = 47,
        DGRAM_GET_MTU = 41,
        DGRAM_SET_MTU = 42,
        DGRAM_MTU_EXCEEDED = 43,
        DGRAM_GET_PEER = 46,
        DGRAM_SET_PEER = 44,
        DGRAM_SET_NEXT_TIMEOUT = 45,
        DGRAM_SET_DONT_FRAG = 48,
        DGRAM_GET_MTU_OVERHEAD = 49,
        DGRAM_SCTP_SET_IN_HANDSHAKE = 50,
        /* SCTP stuff */
        DGRAM_SCTP_ADD_AUTH_KEY = 51,
        DGRAM_SCTP_NEXT_AUTH_KEY = 52,
        DGRAM_SCTP_AUTH_CCS_RCVD = 53,
        DGRAM_SCTP_GET_SNDINFO = 60,
        DGRAM_SCTP_SET_SNDINFO = 61,
        DGRAM_SCTP_GET_RCVINFO = 62,
        DGRAM_SCTP_SET_RCVINFO = 63,
        DGRAM_SCTP_GET_PRINFO = 64,
        DGRAM_SCTP_SET_PRINFO = 65,
        DGRAM_SCTP_SAVE_SHUTDOWN = 70,

        DGRAM_SET_PEEK_MODE = 71,

        C_SET_CONNECT = 100,
        C_DO_STATE_MACHINE = 101,
        C_SET_NBIO = 102,
        //  C_SET_PROXY_PARAM = 103,
        C_SET_FD = 104,
        C_GET_FD = 105,
        C_SET_FILE_PTR = 106,
        C_GET_FILE_PTR = 107,
        C_SET_FILENAME = 108,
        C_SET_SSL = 109,
        C_GET_SSL = 110,
        C_SET_MD = 111,
        C_GET_MD = 112,
        C_GET_CIPHER_STATUS = 113,
        C_SET_BUF_MEM = 114,
        C_GET_BUF_MEM_PTR = 115,
        C_GET_BUFF_NUM_LINES = 116,
        C_SET_BUFF_SIZE = 117,
        C_SET_ACCEPT = 118,
        C_SSL_MODE = 119,
        C_GET_MD_CTX = 120,
        //  C_GET_PROXY_PARAM = 121,
        C_SET_BUFF_READ_DATA = 122,
        C_GET_CONNECT = 123,
        C_GET_ACCEPT = 124,
        C_SET_SSL_RENEGOTIATE_BYTES = 125,
        C_GET_SSL_NUM_RENEGOTIATES = 126,
        C_SET_SSL_RENEGOTIATE_TIMEOUT = 127,
        C_FILE_SEEK = 128,
        C_GET_CIPHER_CTX = 129,
        C_SET_BUF_MEM_EOF_RETURN = 130,
        C_SET_BIND_MODE = 131,
        C_GET_BIND_MODE = 132,
        C_FILE_TELL = 133,
        C_GET_SOCKS = 134,
        C_SET_SOCKS = 135,

        C_SET_WRITE_BUF_SIZE = 136,
        C_GET_WRITE_BUF_SIZE = 137,
        C_MAKE_BIO_PAIR = 138,
        C_DESTROY_BIO_PAIR = 139,
        C_GET_WRITE_GUARANTEE = 140,
        C_GET_READ_REQUEST = 141,
        C_SHUTDOWN_WR = 142,
        C_NREAD0 = 143,
        C_NREAD = 144,
        C_NWRITE0 = 145,
        C_NWRITE = 146,
        C_RESET_READ_REQUEST = 147,
        C_SET_MD_CTX = 148,

        C_SET_PREFIX = 149,
        C_GET_PREFIX = 150,
        C_SET_SUFFIX = 151,
        C_GET_SUFFIX = 152,

        C_SET_EX_ARG = 153,
        C_GET_EX_ARG = 154,

        C_SET_CONNECT_MODE = 155,
    }
}