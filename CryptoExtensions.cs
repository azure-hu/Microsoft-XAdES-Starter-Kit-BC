namespace Microsoft.Xades
{
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Xml;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;

    public static class CryptoExtensions
    {
        private static IReadOnlyDictionary<String, DerObjectIdentifier> knownAlgorithms;

        static CryptoExtensions()
        {
            Dictionary<String, DerObjectIdentifier> algs = new Dictionary<String, DerObjectIdentifier>();
            algs.Add(SignedXml.XmlDsigSHA1Url, X509ObjectIdentifiers.IdSha1);
            algs.Add(SignedXml.XmlDsigMoreSHA224Url, NistObjectIdentifiers.IdSha224);
            algs.Add(SignedXml.XmlDsigSHA256Url, NistObjectIdentifiers.IdSha256);
            algs.Add(SignedXml.XmlDsigSHA384Url, NistObjectIdentifiers.IdSha384);
            algs.Add(SignedXml.XmlDsigSHA512Url, NistObjectIdentifiers.IdSha512);
            knownAlgorithms = new ReadOnlyDictionary<String, DerObjectIdentifier>(algs);
        }

        public static Byte[] GetCertHash(this X509Certificate cer, String digestUrl = SignedXml.XmlDsigSHA1Url)
        {
            Byte[] certBytes = cer.GetEncoded();
            IDigest digest = CryptoHelpers.CreateFromName<IDigest>(digestUrl);
            digest.BlockUpdate(certBytes, 0, certBytes.Length);
            Byte[] certHash = DigestUtilities.DoFinal(digest);
            return certHash;
        }

        public static DerObjectIdentifier GetDerOid(String algorithmUri)
        {
            if (knownAlgorithms.ContainsKey(algorithmUri))
            {
                return knownAlgorithms[algorithmUri];
            }
            else
            {
                throw new NotSupportedException($"Algoriithm {algorithmUri} not known.");
            }
            
        }
    }
}
