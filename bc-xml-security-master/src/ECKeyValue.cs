// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Xml;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class ECKeyValue : KeyInfoClause
    {
        private ECPublicKeyParameters _key;

        //
        // public constructors
        //

        public ECKeyValue(ECPublicKeyParameters key) => _key = key;

        //
        // public properties
        //

        public ECPublicKeyParameters Key
        {
            get => _key;
            set => _key = value;
        }

        //
        // public methods
        //

        /// <summary>
        /// Create an XML representation.
        /// </summary>
        /// <remarks>
        /// Based upon https://www.w3.org/TR/xmldsig-core/#sec-ECKeyValue
        /// </remarks>
        /// <returns>
        /// An <see cref="XmlElement"/> containing the XML representation.
        /// </returns>
        public override XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };
            return GetXml(xmlDocument);
        }

        private const string KeyValueElementName = "KeyValue";
        private const string ECKeyValueElementName = "ECAKeyValue";

        //Optional ECParameters - NamedCurve Choice
        private const string ECParametersElementName = "ECParameters";
        private const string NamedCurveElementName = "NamedCurve";

        //Optional Members
        private const string IdAttributeName = "Id";

        //Mandatory Members
        private const string PublicKeyElementName = "PublicKey";

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement keyValueElement = xmlDocument.CreateElement(KeyValueElementName, SignedXml.XmlDsigNamespaceUrl);
            XmlElement ecKeyValueElement = xmlDocument.CreateElement(ECKeyValueElementName, SignedXml.XmlDsig11NamespaceUrl);

            DerObjectIdentifier curveOid = FindECCurveOid(_key);
            XmlElement namedCurveElement = xmlDocument.CreateElement(NamedCurveElementName, SignedXml.XmlDsig11NamespaceUrl);
            namedCurveElement.AppendChild(xmlDocument.CreateTextNode(string.Format("urn:oid:{0}", curveOid.ToString())));
            ecKeyValueElement.AppendChild(namedCurveElement);

            XmlElement publicKeyElement = xmlDocument.CreateElement(PublicKeyElementName, SignedXml.XmlDsig11NamespaceUrl);
            publicKeyElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(_key.Q.GetEncoded(false))));
            ecKeyValueElement.AppendChild(publicKeyElement);


            keyValueElement.AppendChild(ecKeyValueElement);

            return keyValueElement;
        }

        private DerObjectIdentifier FindECCurveOid(ECPublicKeyParameters publicKey)
        {
            DerObjectIdentifier curveOid = null;
            ECDomainParameters pubKeyDomainParams = publicKey.Parameters;
            foreach (string curveName in ECNamedCurveTable.Names)
            {
                X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
                if (curveParams.Curve.Equals(pubKeyDomainParams.Curve)
                     && curveParams.G.Equals(pubKeyDomainParams.G)
                     && curveParams.H.Equals(pubKeyDomainParams.H)
                     && curveParams.N.Equals(pubKeyDomainParams.N))
                {
                    curveOid = ECNamedCurveTable.GetOid(curveName);
                }
            }

            return curveOid;
        }

        /// <summary>
        /// Deserialize from the XML representation.
        /// </summary>
        /// <remarks>
        /// Based upon https://www.w3.org/TR/xmldsig-core/#sec-ECKeyValue
        /// </remarks>
        /// <param name="value">
        /// An <see cref="XmlElement"/> containing the XML representation. This cannot be null.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="value"/> cannot be null.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The XML has the incorrect schema or the EC parameters are invalid.
        /// </exception>
        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (value.Name != KeyValueElementName
                || value.NamespaceURI != SignedXml.XmlDsigNamespaceUrl)
            {
                throw new System.Security.Cryptography.CryptographicException($"Root element must be {KeyValueElementName} element in namepsace {SignedXml.XmlDsigNamespaceUrl}");
            }

            string xmlDsigNamespacePrefix = SignedXml.XmlDsigNamespacePrefix;
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace(xmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            string xmlDsig11NamespacePrefix = SignedXml.XmlDsig11NamespacePrefix;
            xmlNamespaceManager.AddNamespace(xmlDsig11NamespacePrefix, SignedXml.XmlDsig11NamespaceUrl);

            XmlNode ecKeyValueElement = value.SelectSingleNode($"{xmlDsig11NamespacePrefix}:{ECKeyValueElementName}", xmlNamespaceManager);
            if (ecKeyValueElement == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"{KeyValueElementName} must contain child element {ECKeyValueElementName}");
            }

            XmlNode publicKeyNode = ecKeyValueElement.SelectSingleNode($"{xmlDsig11NamespacePrefix}:{PublicKeyElementName}", xmlNamespaceManager);
            if (publicKeyNode == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"{PublicKeyElementName} is missing");
            }

            XmlNode ecParametersNode = ecKeyValueElement.SelectSingleNode($"{xmlDsig11NamespacePrefix}:{ECParametersElementName}", xmlNamespaceManager);
            XmlNode namedCurveNode = ecKeyValueElement.SelectSingleNode($"{xmlDsig11NamespacePrefix}:{NamedCurveElementName}", xmlNamespaceManager);

            if (ecParametersNode == null && namedCurveNode == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"Either {ECParametersElementName} or {NamedCurveElementName} must exist!");
            }

            if (ecParametersNode != null && namedCurveNode != null)
            {
                throw new System.Security.Cryptography.CryptographicException($"Only {ECParametersElementName} or {NamedCurveElementName} must exist!");
            }

            try
            {
                if (namedCurveNode == null)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    byte[] publicKeyBytes = Convert.FromBase64String(publicKeyNode.InnerText);
                    string namedCurveOid = namedCurveNode.InnerText.Replace("urn:oid:", string.Empty);
                    Key = CreatePublicKeyParams(publicKeyBytes, namedCurveOid);
                }
            }
            catch (Exception ex)
            {
                throw new System.Security.Cryptography.CryptographicException($"An error occurred parsing the key components", ex);
            }
        }

        private ECPublicKeyParameters CreatePublicKeyParams(byte[] publicKeyBytes, string namedCurveOid)
        {
            X9ECParameters ecCurve = ECNamedCurveTable.GetByOid(new DerObjectIdentifier(namedCurveOid));
            ECDomainParameters domainParams = new ECDomainParameters(ecCurve);
            byte[] decodedBytes;
            using (MemoryStream ms = new MemoryStream(publicKeyBytes))
            {
                int first = ms.ReadByte();

                // Decode the public ephemeral key
                switch (first)
                {
                    case 0x00: // infinity
                        throw new IOException("Sender's public key invalid.");

                    case 0x02: // compressed
                    case 0x03: // Byte length calculated as in ECPoint.getEncoded();
                        decodedBytes = new byte[1 + (domainParams.Curve.FieldSize + 7) / 8];
                        break;

                    case 0x04: // uncompressed or
                    case 0x06: // hybrid
                    case 0x07: // Byte length calculated as in ECPoint.getEncoded();
                        decodedBytes = new byte[1 + 2 * ((domainParams.Curve.FieldSize + 7) / 8)];
                        break;

                    default:
                        throw new IOException("Sender's public key has invalid point encoding 0x" + publicKeyBytes[0].ToString("X2"));
                }

                decodedBytes[0] = (byte)first;
                Streams.ReadFully(ms, decodedBytes, 1, decodedBytes.Length - 1);
            }
            ECPoint q = domainParams.Curve.DecodePoint(decodedBytes);
            return new ECPublicKeyParameters(q, domainParams);
        }
    }
}
