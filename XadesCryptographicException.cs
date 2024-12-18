﻿namespace Microsoft.Xades.BC
{
    using System;
    using System.Runtime.Serialization;
    using System.Security.Cryptography;

    public class XadesCryptographicException : CryptographicException
    {
        public XadesCryptographicException()
        {
        }

        public XadesCryptographicException(String message) : base(message)
        {
        }

        public XadesCryptographicException(Int32 hr) : base(hr)
        {
        }

        public XadesCryptographicException(String format, String insert) : base(format, insert)
        {
        }

        public XadesCryptographicException(String message, Exception inner) : base(message, inner)
        {
        }

        protected XadesCryptographicException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
