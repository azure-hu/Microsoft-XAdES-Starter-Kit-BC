// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Xml;
using XmlSec.Crypto;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class ECKeyValue : KeyInfoClause
    {
        private ECPublicKeyParameters _key;

        //
        // public constructors
        //

        public ECKeyValue()
        {
            AsymmetricCipherKeyPair pair = ECKeyUtils.GenerateEphemeralKeyPair();
            this._key = (ECPublicKeyParameters)pair.Public;
        }

        public ECKeyValue(ECPublicKeyParameters key)
        {
            this._key = key;
        }

        //
        // public properties
        //

        public ECPublicKeyParameters Key
        {
            get { return this._key; }
            set { this._key = value; }
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
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            return this.GetXml(xmlDocument);
        }

        private const String KeyValueElementName = "KeyValue";
        private const String ECKeyValueElementName = "ECAKeyValue";

        //Optional ECParameters - NamedCurve Choice
        private const String ECParametersElementName = "ECParameters";
        private const String NamedCurveElementName = "NamedCurve";

        //Optional Members
        private const String IdAttributeName = "Id";

        //Mandatory Members
        private const String PublicKeyElementName = "PublicKey";

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement keyValueElement = xmlDocument.CreateElement(KeyValueElementName, SignedXml.XmlDsigNamespaceUrl);
            XmlElement ecKeyValueElement = xmlDocument.CreateElement(ECKeyValueElementName, SignedXml.XmlDsig11NamespaceUrl);

            XmlElement namedCurveElement = xmlDocument.CreateElement(NamedCurveElementName, SignedXml.XmlDsig11NamespaceUrl);
            namedCurveElement.AppendChild(xmlDocument.CreateTextNode(ECKeyUtils.GetCurveOidUri(this._key)));
            ecKeyValueElement.AppendChild(namedCurveElement);

            XmlElement publicKeyElement = xmlDocument.CreateElement(PublicKeyElementName, SignedXml.XmlDsig11NamespaceUrl);
            publicKeyElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Q.GetEncoded(false))));
            ecKeyValueElement.AppendChild(publicKeyElement);


            keyValueElement.AppendChild(ecKeyValueElement);

            return keyValueElement;
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

            String xmlDsigNamespacePrefix = SignedXml.XmlDsigNamespacePrefix;
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace(xmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            String xmlDsig11NamespacePrefix = SignedXml.XmlDsig11NamespacePrefix;
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
                    Byte[] publicKeyBytes = Convert.FromBase64String(publicKeyNode.InnerText);
                    String namedCurveOid = namedCurveNode.InnerText.Replace("urn:oid:", String.Empty);
                    this.Key = ECKeyUtils.GetPublicKeyParams(publicKeyBytes, namedCurveOid);
                }
            }
            catch (Exception ex)
            {
                throw new System.Security.Cryptography.CryptographicException($"An error occurred parsing the key components", ex);
            }
        }
    }
}
