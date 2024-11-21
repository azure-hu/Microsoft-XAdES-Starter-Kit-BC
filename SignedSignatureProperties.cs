// SignedSignatureProperties.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
// Published under the CECILL-B Free Software license agreement.
// (http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.txt)
// 
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
// WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
// WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
// THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION WITH THE USE OF THIS CODE 
// AND INFORMATION REMAINS WITH THE USER. 
//

using System;
using System.Xml;

namespace Microsoft.Xades.BC
{
    /// <summary>
    /// The properties that qualify the signature itself or the signer are
    /// included as content of the SignedSignatureProperties element
    /// </summary>
    public class SignedSignatureProperties
    {
        #region Private variables
        private DateTime signingTime;
        private SigningCertificate signingCertificate;
        private SigningCertificateV2 signingCertificateV2;
        private SignaturePolicyIdentifier signaturePolicyIdentifier;
        private SignatureProductionPlace signatureProductionPlace;
        private SignerRole signerRole;
        #endregion

        #region Public properties
        /// <summary>
        /// The signing time property specifies the time at which the signer
        /// performed the signing process. This is a signed property that
        /// qualifies the whole signature. An XML electronic signature aligned
        /// with the present document MUST contain exactly one SigningTime element .
        /// </summary>
        public DateTime SigningTime
        {
            get
            {
                return this.signingTime;
            }
            set
            {
                this.signingTime = value;
            }
        }

        /// <summary>
        /// The SigningCertificate property is designed to prevent the simple
        /// substitution of the certificate. This property contains references
        /// to certificates and digest values computed on them. The certificate
        /// used to verify the signature shall be identified in the sequence;
        /// the signature policy may mandate other certificates be present,
        /// that may include all the certificates up to the point of trust.
        /// This is a signed property that qualifies the signature. An XML
        /// electronic signature aligned with the present document MUST contain
        /// exactly one SigningCertificate.
        /// </summary>
        public SigningCertificate SigningCertificate
        {
            get
            {
                return this.signingCertificate;
            }
            set
            {
                this.signingCertificate = value;
            }
        }

        /// <summary>
        /// The SigningCertificateV2 property is designed to prevent the simple
        /// substitution of the certificate. This property contains references
        /// to certificates and digest values computed on them. The certificate
        /// used to verify the signature shall be identified in the sequence;
        /// the signature policy may mandate other certificates be present,
        /// that may include all the certificates up to the point of trust.
        /// This is a signed property that qualifies the signature. An XML
        /// electronic signature aligned with the present document MUST contain
        /// exactly one SigningCertificateV2.
        /// </summary>
		public SigningCertificateV2 SigningCertificateV2
        {
            get
            {
                return this.signingCertificateV2;
            }
            set
            {
                this.signingCertificateV2 = value;
            }
        }

        /// <summary>
        /// The signature policy is a set of rules for the creation and
        /// validation of an electronic signature, under which the signature
        /// can be determined to be valid. A given legal/contractual context
        /// may recognize a particular signature policy as meeting its
        /// requirements.
        /// An XML electronic signature aligned with the present document MUST
        /// contain exactly one SignaturePolicyIdentifier element.
        /// </summary>
        public SignaturePolicyIdentifier SignaturePolicyIdentifier
        {
            get
            {
                return this.signaturePolicyIdentifier;
            }
            set
            {
                this.signaturePolicyIdentifier = value;
            }
        }

        /// <summary>
        /// In some transactions the purported place where the signer was at the time
        /// of signature creation may need to be indicated. In order to provide this
        /// information a new property may be included in the signature.
        /// This property specifies an address associated with the signer at a
        /// particular geographical (e.g. city) location.
        /// This is a signed property that qualifies the signer.
        /// An XML electronic signature aligned with the present document MAY contain
        /// at most one SignatureProductionPlace element.
        /// </summary>
        public SignatureProductionPlace SignatureProductionPlace
        {
            get
            {
                return this.signatureProductionPlace;
            }
            set
            {
                this.signatureProductionPlace = value;
            }
        }

        /// <summary>
        /// According to what has been stated in the Introduction clause, an
        /// electronic signature produced in accordance with the present document
        /// incorporates: "a commitment that has been explicitly endorsed under a
        /// signature policy, at a given time, by a signer under an identifier,
        /// e.g. a name or a pseudonym, and optionally a role".
        /// While the name of the signer is important, the position of the signer
        /// within a company or an organization can be even more important. Some
        /// contracts may only be valid if signed by a user in a particular role,
        /// e.g. a Sales Director. In many cases who the sales Director really is,
        /// is not that important but being sure that the signer is empowered by his
        /// company to be the Sales Director is fundamental.
        /// </summary>
        public SignerRole SignerRole
        {
            get
            {
                return this.signerRole;
            }
            set
            {
                this.signerRole = value;
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Default constructor
        /// </summary>
        public SignedSignatureProperties()
        {
            this.signingTime = DateTime.MinValue;
            this.signingCertificate = new SigningCertificate();
            this.SigningCertificateV2 = new SigningCertificateV2();
            this.signaturePolicyIdentifier = new SignaturePolicyIdentifier();
            this.signatureProductionPlace = new SignatureProductionPlace();
            this.signerRole = new SignerRole();
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Check to see if something has changed in this instance and needs to be serialized
        /// </summary>
        /// <returns>Flag indicating if a member needs serialization</returns>
        public Boolean HasChanged()
        {
            //Should always be serialized
            Boolean retVal = true;
            return retVal;
        }

        /// <summary>
        /// Load state from an XML element
        /// </summary>
        /// <param name="xmlElement">XML element containing new state</param>
        public void LoadXml(XmlElement xmlElement)
        {
            XmlNamespaceManager xmlNamespaceManager;
            XmlNodeList xmlNodeList;

            if (xmlElement == null)
            {
                throw new ArgumentNullException(nameof(xmlElement));
            }

            xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace(XadesSignedXml.XadesNamespacePrefix, XadesSignedXml.XadesNamespaceUri);

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":SigningTime", xmlNamespaceManager);
            if (xmlNodeList.Count == 0)
            {
                throw new XadesCryptographicException("SigningTime missing");
            }
            this.SigningTime = XmlConvert.ToDateTime(xmlNodeList.Item(0).InnerText, XmlDateTimeSerializationMode.Local);

            /*
            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":SigningCertificate", xmlNamespaceManager);
            if (xmlNodeList.Count == 0)
            {
                throw new XadesCryptographicException("SigningCertificate missing");
            }
            */
            xmlNodeList = FindSigningCertificate(xmlElement, xmlNamespaceManager, out Boolean newVersion);
            if (newVersion)
            {
                this.SigningCertificateV2 = new SigningCertificateV2();
                this.SigningCertificateV2.LoadXml((XmlElement)xmlNodeList.Item(0));
            }
            else
            {
                this.SigningCertificate = new SigningCertificate();
                this.SigningCertificate.LoadXml((XmlElement)xmlNodeList.Item(0));
            }

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":SignaturePolicyIdentifier", xmlNamespaceManager);
            if (xmlNodeList.Count == 0)
            {
                throw new XadesCryptographicException("SignaturePolicyIdentifier missing");
            }
            this.SignaturePolicyIdentifier = new SignaturePolicyIdentifier();
            this.SignaturePolicyIdentifier.LoadXml((XmlElement)xmlNodeList.Item(0));

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":SignatureProductionPlace", xmlNamespaceManager);
            if (xmlNodeList.Count != 0)
            {
                this.SignatureProductionPlace = new SignatureProductionPlace();
                this.SignatureProductionPlace.LoadXml((XmlElement)xmlNodeList.Item(0));
            }
            else
            {
                this.SignatureProductionPlace = null;
            }

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":SignerRole", xmlNamespaceManager);
            if (xmlNodeList.Count != 0)
            {
                this.SignerRole = new SignerRole();
                this.SignerRole.LoadXml((XmlElement)xmlNodeList.Item(0));
            }
            else
            {
                this.SignerRole = null;
            }
        }

        /// <summary>
        /// Returns the XML representation of the this object
        /// </summary>
        /// <returns>XML element containing the state of this object</returns>
        public XmlElement GetXml()
        {
            XmlDocument creationXmlDocument;
            XmlElement retVal;
            XmlElement bufferXmlElement;

            creationXmlDocument = new XmlDocument();
            retVal = creationXmlDocument.CreateElement(XadesSignedXml.XadesNamespacePrefix, "SignedSignatureProperties", XadesSignedXml.XadesNamespaceUri);

            if (this.SigningTime == DateTime.MinValue)
            { 
            	//SigningTime should be available
                this.SigningTime = DateTime.Now;
            }
            bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XadesNamespacePrefix, "SigningTime", XadesSignedXml.XadesNamespaceUri);
            bufferXmlElement.InnerText = Convert.ToString(this.SigningTime.ToString("s")); //ISO 8601 format as required in http://www.w3.org/TR/xmlschema-2/#dateTime
            retVal.AppendChild(bufferXmlElement);

            if (this.SigningCertificate != null && this.SigningCertificate.CertCollection.Count > 0 && this.SigningCertificate.HasChanged())
            {
                retVal.AppendChild(creationXmlDocument.ImportNode(this.SigningCertificate.GetXml(), true));
            }
            else if (this.SigningCertificateV2 != null && this.SigningCertificateV2.CertCollection.Count > 0 && this.SigningCertificateV2.HasChanged())
            {
                retVal.AppendChild(creationXmlDocument.ImportNode(this.SigningCertificateV2.GetXml(), true));
            }
            else
            {
                throw new XadesCryptographicException("SigningCertificate element missing in SignedSignatureProperties");
            }

            if (this.SignaturePolicyIdentifier != null && this.SignaturePolicyIdentifier.HasChanged())
            {
                retVal.AppendChild(creationXmlDocument.ImportNode(this.SignaturePolicyIdentifier.GetXml(), true));
            }
            else
            {
                throw new XadesCryptographicException("SignaturePolicyIdentifier element missing in SignedSignatureProperties");
            }

            if (this.SignatureProductionPlace != null && this.SignatureProductionPlace.HasChanged())
            {
                retVal.AppendChild(creationXmlDocument.ImportNode(this.SignatureProductionPlace.GetXml(), true));
            }

            if (this.SignerRole != null && this.SignerRole.HasChanged())
            {
                retVal.AppendChild(creationXmlDocument.ImportNode(this.SignerRole.GetXml(), true));
            }

            return retVal;
        }
        #endregion

        private static XmlNodeList FindSigningCertificate(XmlElement xmlElement, XmlNamespaceManager xmlNamespaceManager, out bool newVersion)
        {
            XmlNodeList xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":SigningCertificate", xmlNamespaceManager);
            if (xmlNodeList != null && xmlNodeList.Count > 0)
            {
                newVersion = false;
                return xmlNodeList;
            }

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":SigningCertificateV2", xmlNamespaceManager);
            if (xmlNodeList != null && xmlNodeList.Count > 0)
            {
                newVersion = true;
                return xmlNodeList;
            }

            throw new XadesCryptographicException("SigningCertificate or SigningCertificateV2 missing");
        }
    }
}
