// XadesSignedXml.cs
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

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Xml;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace Microsoft.Xades.BC
{
    /// <summary>
    /// Types of signature standards that can be contained in XadesSignedXml class instance
    /// </summary>
    public enum KnownSignatureStandard
    {
        /// <summary>
        /// XML Digital Signature (XMLDSIG)
        /// </summary>
        XmlDsig,
        /// <summary>
        /// XML Advanced Electronic Signature (XAdES) 
        /// </summary>
        Xades
    }

    /// <summary>
    /// Bitmasks to indicate which checks need to be executed on the XAdES signature
    /// </summary>
    [FlagsAttribute]
    public enum XadesCheckSignatureMasks : UInt64
    {
        /// <summary>
        /// Check the signature of the underlying XMLDSIG signature
        /// </summary>
        CheckXmldsigSignature = 0x01,
        /// <summary>
        /// Validate the XML representation of the signature against the XAdES and XMLDSIG schemas
        /// </summary>
        ValidateAgainstSchema = 0x02,
        /// <summary>
        /// Check to see if first XMLDSIG certificate has same hashvalue as first XAdES SignatureCertificate
        /// </summary>
        CheckSameCertificate = 0x04,
        /// <summary>
        /// Check if there is a HashDataInfo for each reference if there is a AllDataObjectsTimeStamp
        /// </summary>
        CheckAllReferencesExistInAllDataObjectsTimeStamp = 0x08,
        /// <summary>
        /// Check if the HashDataInfo of each IndividualDataObjectsTimeStamp points to existing Reference
        /// </summary>
        CheckAllHashDataInfosInIndividualDataObjectsTimeStamp = 0x10,
        /// <summary>
        /// Perform XAdES checks on contained counter signatures 
        /// </summary>
        CheckCounterSignatures = 0x20,
        /// <summary>
        /// Counter signatures should all contain a reference to the parent signature SignatureValue element
        /// </summary>
        CheckCounterSignaturesReference = 0x40,
        /// <summary>
        /// Check if each ObjectReference in CommitmentTypeIndication points to Reference element
        /// </summary>
        CheckObjectReferencesInCommitmentTypeIndication = 0x80,
        /// <summary>
        /// Check if at least ClaimedRoles or CertifiedRoles present in SignerRole
        /// </summary>
        CheckIfClaimedRolesOrCertifiedRolesPresentInSignerRole = 0x0100,
        /// <summary>
        /// Check if HashDataInfo of SignatureTimeStamp points to SignatureValue
        /// </summary>
        CheckHashDataInfoOfSignatureTimeStampPointsToSignatureValue = 0x0200,
        /// <summary>
        /// Check if the QualifyingProperties Target attribute points to the signature element
        /// </summary>
        CheckQualifyingPropertiesTarget = 0x0400,
        /// <summary>
        /// Check that QualifyingProperties occur in one Object, check that there is only one QualifyingProperties and that signed properties occur in one QualifyingProperties element
        /// </summary>
        CheckQualifyingProperties = 0x0800,
        /// <summary>
        /// Check if all required HashDataInfos are present on SigAndRefsTimeStamp
        /// </summary>
        CheckSigAndRefsTimeStampHashDataInfos = 0x1000,
        /// <summary>
        /// Check if all required HashDataInfos are present on RefsOnlyTimeStamp
        /// </summary>
        CheckRefsOnlyTimeStampHashDataInfos = 0x2000,
        /// <summary>
        /// Check if all required HashDataInfos are present on ArchiveTimeStamp
        /// </summary>
        CheckArchiveTimeStampHashDataInfos = 0x4000,
        /// <summary>
        /// Check if a XAdES-C signature is also a XAdES-T signature
        /// </summary>
        CheckXadesCIsXadesT = 0x8000,
        /// <summary>
        /// Check if a XAdES-XL signature is also a XAdES-X signature
        /// </summary>
        CheckXadesXLIsXadesX = 0x010000,
        /// <summary>
        /// Check if CertificateValues match CertificateRefs
        /// </summary>
        CheckCertificateValuesMatchCertificateRefs = 0x020000,
        /// <summary>
        /// Check if RevocationValues match RevocationRefs
        /// </summary>
        CheckRevocationValuesMatchRevocationRefs = 0x040000,
        /// <summary>
        /// Do all known tests on XAdES signature
        /// </summary>
        AllChecks = 0xFFFFFF
    }

    /// <summary>
    /// Facade class for the XAdES signature library.  The class inherits from
    /// the Org.BouncyCastle.Crypto.Xml.SignedXml class and is backwards
    /// compatible with it, so this class can host xmldsig signatures and XAdES
    /// signatures.  The property SignatureStandard will indicate the type of the
    /// signature: XMLDSIG or XAdES.
    /// </summary>
    public class XadesSignedXml : Org.BouncyCastle.Crypto.Xml.SignedXml
    {
        #region Constants
        /// <summary>
        /// The XAdES XML namespace URI
        /// </summary>
        public const String XadesNamespaceUri = "http://uri.etsi.org/01903/v1.3.2#";

        /// <summary>
        /// Mandated type name for the Uri reference to the SignedProperties element
        /// </summary>
        public const String SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";
        #endregion

        #region Private variables
        private static readonly String[] idAttrs = new String[]
        {
            "_id",
            "_Id",
            "_ID"
        };

        private KnownSignatureStandard signatureStandard;

        private XmlDocument cachedXadesObjectDocument;
        private String signedPropertiesIdBuffer;
        private String signatureValueId;
        private Boolean validationErrorOccurred;
        private String validationErrorDescription;
        private String signedInfoIdBuffer;
        #endregion

        #region Public properties
        /// <summary>
        /// Property indicating the type of signature (XmlDsig or XAdES)
        /// </summary>
        public KnownSignatureStandard SignatureStandard
        {
            get
            {
                return this.signatureStandard;
            }
        }

        /// <summary>
        /// Read-only property containing XAdES information
        /// </summary>
        public XadesObject XadesObject
        {
            get
            {
                XadesObject retVal = new XadesObject();

                retVal.LoadXml(this.GetXadesObjectElement(this.GetXml()), this.GetXml());

                return retVal;
            }
        }

        /// <summary>
        /// Setting this property will add an ID attribute to the SignatureValue element.
        /// This is required when constructing a XAdES-T signature.
        /// </summary>
        public String SignatureValueId
        {
            get
            {
                return this.signatureValueId;
            }
            set
            {
                this.signatureValueId = value;
            }
        }

        /// <summary>
        /// This property allows to access and modify the unsigned properties
        /// after the XAdES object has been added to the signature.
        /// Because the unsigned properties are part of a location in the
        /// signature that is not used when computing the signature, it is save
        /// to modify them even after the XMLDSIG signature has been computed.
        /// This is needed when XAdES objects that depend on the XMLDSIG
        /// signature value need to be added to the signature. The
        /// SignatureTimeStamp element is such a property, it can only be
        /// created when the XMLDSIG signature has been computed.
        /// </summary>
        public UnsignedProperties UnsignedProperties
        {
            get
            {
                XmlElement dataObjectXmlElement;
                Org.BouncyCastle.Crypto.Xml.DataObject xadesDataObject;
                XmlNamespaceManager xmlNamespaceManager;
                XmlNodeList xmlNodeList;
                UnsignedProperties retVal;

                retVal = new UnsignedProperties();
                xadesDataObject = this.GetXadesDataObject();
                if (xadesDataObject != null)
                {
                    dataObjectXmlElement = xadesDataObject.GetXml();
                    xmlNamespaceManager = new XmlNamespaceManager(dataObjectXmlElement.OwnerDocument.NameTable);
                    xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);
                    xmlNodeList = dataObjectXmlElement.SelectNodes("xsd:QualifyingProperties/xsd:UnsignedProperties", xmlNamespaceManager);
                    if (xmlNodeList.Count != 0)
                    {
                        retVal = new UnsignedProperties();
                        retVal.LoadXml((XmlElement)xmlNodeList[0], (XmlElement)xmlNodeList[0]);
                    }
                }
                else
                {
                    throw new XadesCryptographicException("XAdES object not found. Use AddXadesObject() before accessing UnsignedProperties.");
                }

                return retVal;
            }

            set
            {
                XmlElement dataObjectXmlElement = null;
                DataObject xadesDataObject, newXadesDataObject;
                XmlNamespaceManager xmlNamespaceManager;
                XmlNodeList qualifyingPropertiesXmlNodeList;
                XmlNodeList unsignedPropertiesXmlNodeList;

                xadesDataObject = this.GetXadesDataObject();
                if (xadesDataObject != null)
                {
                    dataObjectXmlElement = xadesDataObject.GetXml();
                    xmlNamespaceManager = new XmlNamespaceManager(dataObjectXmlElement.OwnerDocument.NameTable);
                    xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);
                    qualifyingPropertiesXmlNodeList = dataObjectXmlElement.SelectNodes("xsd:QualifyingProperties", xmlNamespaceManager);
                    unsignedPropertiesXmlNodeList = dataObjectXmlElement.SelectNodes("xsd:QualifyingProperties/xsd:UnsignedProperties", xmlNamespaceManager);
                    if (unsignedPropertiesXmlNodeList.Count != 0)
                    {
                        qualifyingPropertiesXmlNodeList[0].RemoveChild(unsignedPropertiesXmlNodeList[0]);
                    }
                    qualifyingPropertiesXmlNodeList[0].AppendChild(dataObjectXmlElement.OwnerDocument.ImportNode(value.GetXml(), true));

                    newXadesDataObject = new DataObject();
                    newXadesDataObject.LoadXml(dataObjectXmlElement);
                    xadesDataObject.Data = newXadesDataObject.Data;
                }
                else
                {
                    throw new XadesCryptographicException("XAdES object not found. Use AddXadesObject() before accessing UnsignedProperties.");
                }
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Default constructor for the XadesSignedXml class
        /// </summary>
        public XadesSignedXml()
            : base()
        {
            this.cachedXadesObjectDocument = null;
            this.signatureStandard = KnownSignatureStandard.XmlDsig;
        }

        /// <summary>
        /// Constructor for the XadesSignedXml class
        /// </summary>
        /// <param name="signatureElement">XmlElement used to create the instance</param>
        public XadesSignedXml(XmlElement signatureElement)
            : base(signatureElement)
        {
            this.cachedXadesObjectDocument = null;
        }

        /// <summary>
        /// Constructor for the XadesSignedXml class
        /// </summary>
        /// <param name="signatureDocument">XmlDocument used to create the instance</param>
        public XadesSignedXml(System.Xml.XmlDocument signatureDocument)
            : base(signatureDocument)
        {
            this.cachedXadesObjectDocument = null;
        }
        #endregion

        #region Public methods

        /// <summary>
        /// Load state from an XML element
        /// </summary>
        /// <param name="xmlElement">The XML element from which to load the XadesSignedXml state</param>
        public new void LoadXml(System.Xml.XmlElement xmlElement)
        {
            this.cachedXadesObjectDocument = null;
            this.signatureValueId = null;
            base.LoadXml(xmlElement);

            XmlNode idAttribute = xmlElement.Attributes.GetNamedItem("Id");
            if (idAttribute != null)
            {
                this.Signature.Id = idAttribute.Value;
            }
            this.SetSignatureStandard(xmlElement);

            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            XmlNodeList xmlNodeList = xmlElement.SelectNodes("ds:SignatureValue", xmlNamespaceManager);
            if (xmlNodeList.Count > 0)
            {
                if (((XmlElement)xmlNodeList[0]).HasAttribute("Id"))
                {
                    this.signatureValueId = ((XmlElement)xmlNodeList[0]).Attributes["Id"].Value;
                }
            }

            xmlNodeList = xmlElement.SelectNodes("ds:SignedInfo", xmlNamespaceManager);
            if (xmlNodeList.Count > 0)
            {
                if (((XmlElement)xmlNodeList[0]).HasAttribute("Id"))
                {
                    this.signedInfoIdBuffer = ((XmlElement)xmlNodeList[0]).Attributes["Id"].Value;
                }
                else
                {
                    this.signedInfoIdBuffer = null;
                }
            }
        }

        /// <summary>
        /// Returns the XML representation of the this object
        /// </summary>
        /// <returns>XML element containing the state of this object</returns>
        public new XmlElement GetXml()
        {
            XmlElement retVal;
            XmlNodeList xmlNodeList;
            XmlNamespaceManager xmlNamespaceManager;

            retVal = base.GetXml();
            if (this.signatureValueId != null && this.signatureValueId != "")
            { //Id on Signature value is needed for XAdES-T. We inject it here.
                xmlNamespaceManager = new XmlNamespaceManager(retVal.OwnerDocument.NameTable);
                xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
                xmlNodeList = retVal.SelectNodes("ds:SignatureValue", xmlNamespaceManager);
                if (xmlNodeList.Count > 0)
                {
                    ((XmlElement)xmlNodeList[0]).SetAttribute("Id", this.signatureValueId);
                }
            }

            // Add "ds" namespace prefix to all XmlDsig nodes in the signature
            //SetPrefix("ds", retVal, SignedXml.XmlDsigNamespaceUrl);
            this.SetPrefixes(retVal);

            return retVal;
        }

        /// <summary>
        /// Overridden virtual method to be able to find the nested SignedProperties
        /// element inside of the XAdES object
        /// </summary>
        /// <param name="xmlDocument">Document in which to find the Id</param>
        /// <param name="idValue">Value of the Id to look for</param>
        /// <returns>XmlElement with requested Id</returns>
        public override XmlElement GetIdElement(XmlDocument xmlDocument, String idValue)
        {
            // check to see if it's a standard ID reference
            XmlElement retVal = null;

            if (idValue == this.signedPropertiesIdBuffer)
            {
                retVal = base.GetIdElement(this.cachedXadesObjectDocument, idValue);
                if (retVal != null)
                {
                    return retVal;
                }

                // if not, search for custom ids
                foreach (String idAttr in idAttrs)
                {
                    retVal = this.cachedXadesObjectDocument.SelectSingleNode("//*[@" + idAttr + "=\"" + idValue + "\"]") as XmlElement;
                    if (retVal != null)
                    {
                        break;
                    }
                }
            }
            else
            {
                if (xmlDocument != null)
                {
                    retVal = base.GetIdElement(xmlDocument, idValue);
                    if (retVal != null)
                    {
                        return retVal;
                    }

                    // if not, search for custom ids
                    foreach (String idAttr in idAttrs)
                    {
                        retVal = xmlDocument.SelectSingleNode("//*[@" + idAttr + "=\"" + idValue + "\"]") as XmlElement;
                        if (retVal != null)
                        {
                            break;
                        }
                    }
                }
            }

            return retVal;
        }

        /// <summary>
        /// Add a XAdES object to the signature
        /// </summary>
        /// <param name="xadesObject">XAdES object to add to signature</param>
        public void AddXadesObject(XadesObject xadesObject)
        {
            Reference reference;
            DataObject dataObject;
            XmlElement bufferXmlElement;

            if (this.SignatureStandard != KnownSignatureStandard.Xades)
            {
                dataObject = new DataObject();
                dataObject.Id = xadesObject.Id;
                dataObject.Data = xadesObject.GetXml().ChildNodes;
                this.AddObject(dataObject); //Add the XAdES object

                reference = new Reference();
                this.signedPropertiesIdBuffer = xadesObject.QualifyingProperties.SignedProperties.Id;
                reference.Uri = "#" + this.signedPropertiesIdBuffer;
                reference.Type = SignedPropertiesType;
                this.AddReference(reference); //Add the XAdES object reference

                this.cachedXadesObjectDocument = new XmlDocument();
                bufferXmlElement = xadesObject.GetXml();

                // Add "ds" namespace prefix to all XmlDsig nodes in the XAdES object
                //SetPrefix("ds", bufferXmlElement, SignedXml.XmlDsigNamespaceUrl);
                this.SetPrefixes(bufferXmlElement);

                this.cachedXadesObjectDocument.PreserveWhitespace = true;
                this.cachedXadesObjectDocument.LoadXml(bufferXmlElement.OuterXml); //Cache to XAdES object for later use

                this.signatureStandard = KnownSignatureStandard.Xades;
            }
            else
            {
                throw new XadesCryptographicException("Can't add XAdES object, the signature already contains a XAdES object");
            }
        }

        //jbonilla
        public X509Certificate GetSigningCertificate()
        {
            return new X509Certificate(System.Text.Encoding.ASCII.GetBytes(this.KeyInfo.GetXml().InnerText));
        }

        /// <summary>
        /// Additional tests for XAdES signatures.  These tests focus on
        /// XMLDSIG verification and correct form of the XAdES XML structure
        /// (schema validation and completeness as defined by the XAdES standard).
        /// </summary>
        /// <remarks>
        /// Because of the fact that the XAdES library is intentionally
        /// independent of standards like TSP (RFC3161) or OCSP (RFC2560),
        /// these tests do NOT include any verification of timestamps nor OCSP
        /// responses.
        /// These checks are important and have to be done in the application
        /// built on top of the XAdES library.
        /// </remarks>
        /// <exception cref="System.Exception">Thrown when the signature is not
        /// a XAdES signature.  SignatureStandard should be equal to
        /// <see cref="KnownSignatureStandard.Xades">KnownSignatureStandard.Xades</see>.
        /// Use the CheckSignature method for non-XAdES signatures.</exception>
        /// <param name="xadesCheckSignatureMasks">Bitmask to indicate which
        /// tests need to be done.  This function will call a public virtual
        /// methods for each bit that has been set in this mask.
        /// See the <see cref="XadesCheckSignatureMasks">XadesCheckSignatureMasks</see>
        /// enum for the bitmask definitions.  The virtual test method associated
        /// with a bit in the mask has the same name as enum value name.</param>
        /// <returns>If the function returns true the check was OK.  If the
        /// check fails an exception with a explanatory message is thrown.</returns>
        public Boolean XadesCheckSignature(XadesCheckSignatureMasks xadesCheckSignatureMasks, String digestUrl = SignedXml.XmlDsigSHA1Url)
        {
            Boolean retVal;

            retVal = true;
            if (this.SignatureStandard != KnownSignatureStandard.Xades)
            {
                throw new Exception("SignatureStandard is not XAdES.  CheckSignature returned: " + this.CheckSignature());
            }
            else
            {
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckXmldsigSignature) != 0)
                {
                    retVal &= this.CheckXmldsigSignature();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.ValidateAgainstSchema) != 0)
                {
                    retVal &= this.ValidateAgainstSchema();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckSameCertificate) != 0)
                {
                    retVal &= this.CheckSameCertificate();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckAllReferencesExistInAllDataObjectsTimeStamp) != 0)
                {
                    retVal &= this.CheckAllReferencesExistInAllDataObjectsTimeStamp();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckAllHashDataInfosInIndividualDataObjectsTimeStamp) != 0)
                {
                    retVal &= this.CheckAllHashDataInfosInIndividualDataObjectsTimeStamp();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckCounterSignatures) != 0)
                {
                    retVal &= this.CheckCounterSignatures(xadesCheckSignatureMasks);
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckCounterSignaturesReference) != 0)
                {
                    retVal &= this.CheckCounterSignaturesReference();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckObjectReferencesInCommitmentTypeIndication) != 0)
                {
                    retVal &= this.CheckObjectReferencesInCommitmentTypeIndication();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckIfClaimedRolesOrCertifiedRolesPresentInSignerRole) != 0)
                {
                    retVal &= this.CheckIfClaimedRolesOrCertifiedRolesPresentInSignerRole();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckHashDataInfoOfSignatureTimeStampPointsToSignatureValue) != 0)
                {
                    retVal &= this.CheckHashDataInfoOfSignatureTimeStampPointsToSignatureValue();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckQualifyingPropertiesTarget) != 0)
                {
                    retVal &= this.CheckQualifyingPropertiesTarget();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckQualifyingProperties) != 0)
                {
                    retVal &= this.CheckQualifyingProperties();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckSigAndRefsTimeStampHashDataInfos) != 0)
                {
                    retVal &= this.CheckSigAndRefsTimeStampHashDataInfos();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckRefsOnlyTimeStampHashDataInfos) != 0)
                {
                    retVal &= this.CheckRefsOnlyTimeStampHashDataInfos();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckArchiveTimeStampHashDataInfos) != 0)
                {
                    retVal &= this.CheckArchiveTimeStampHashDataInfos();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckXadesCIsXadesT) != 0)
                {
                    retVal &= this.CheckXadesCIsXadesT();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckXadesXLIsXadesX) != 0)
                {
                    retVal &= this.CheckXadesXLIsXadesX();
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckCertificateValuesMatchCertificateRefs) != 0)
                {
                    retVal &= this.CheckCertificateValuesMatchCertificateRefs(digestUrl);
                }
                if ((xadesCheckSignatureMasks & XadesCheckSignatureMasks.CheckRevocationValuesMatchRevocationRefs) != 0)
                {
                    retVal &= this.CheckRevocationValuesMatchRevocationRefs(digestUrl);
                }
            }

            return retVal;
        }

        #region XadesCheckSignature routines
        /// <summary>
        /// Check the signature of the underlying XMLDSIG signature
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckXmldsigSignature()
        {
            Boolean retVal = false;

            KeyInfo keyInfo = new KeyInfo();
            X509Certificate xmldsigCert = new X509Certificate(System.Text.Encoding.ASCII.GetBytes(this.KeyInfo.GetXml().InnerText));
            keyInfo.AddClause(new KeyInfoX509Data(xmldsigCert));
            this.KeyInfo = keyInfo;

            retVal = this.CheckSignature();
            if (retVal == false)
            {
                throw new XadesCryptographicException("CheckXmldsigSignature() failed");
            }

            return retVal;
        }

        /// <summary>
        /// Validate the XML representation of the signature against the XAdES and XMLDSIG schemas
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean ValidateAgainstSchema()
        {
            Boolean retValue = false;

            Assembly assembly = Assembly.GetExecutingAssembly();
            XmlSchemaSet schemaSet = new XmlSchemaSet();
            XmlSchema xmlSchema;
            Stream schemaStream;

            NameTable xadesNameTable;
            XmlNamespaceManager xmlNamespaceManager;
            XmlParserContext xmlParserContext;

            this.validationErrorOccurred = false;
            this.validationErrorDescription = "";

            try
            {
                schemaStream = assembly.GetManifestResourceStream("Microsoft.Xades.xmldsig-core-schema.xsd");
                xmlSchema = XmlSchema.Read(schemaStream, new ValidationEventHandler(this.SchemaValidationHandler));
                schemaSet.Add(xmlSchema);
                schemaStream.Close();


                schemaStream = assembly.GetManifestResourceStream("Microsoft.Xades.XAdES.xsd");
                xmlSchema = XmlSchema.Read(schemaStream, new ValidationEventHandler(this.SchemaValidationHandler));
                schemaSet.Add(xmlSchema);
                schemaStream.Close();

                if (this.validationErrorOccurred)
                {
                    throw new XadesCryptographicException("Schema read validation error: " + this.validationErrorDescription);
                }
            }
            catch (Exception exception)
            {
                throw new XadesCryptographicException("Problem during access of validation schemas", exception);
            }

            XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
            xmlReaderSettings.ValidationEventHandler += new ValidationEventHandler(this.XmlValidationHandler);
            xmlReaderSettings.ValidationType = ValidationType.Schema;
            xmlReaderSettings.Schemas = schemaSet;
            xmlReaderSettings.ConformanceLevel = ConformanceLevel.Auto;

            xadesNameTable = new NameTable();
            xmlNamespaceManager = new XmlNamespaceManager(xadesNameTable);
            xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

            xmlParserContext = new XmlParserContext(null, xmlNamespaceManager, null, XmlSpace.None);

            XmlTextReader txtReader = new XmlTextReader(this.GetXml().OuterXml, XmlNodeType.Element, xmlParserContext);
            XmlReader reader = XmlReader.Create(txtReader, xmlReaderSettings);
            try
            {
                while (reader.Read())
                {
                    ;
                }

                if (this.validationErrorOccurred)
                {
                    throw new XadesCryptographicException("Schema validation error: " + this.validationErrorDescription);
                }
            }
            catch (Exception exception)
            {
                throw new XadesCryptographicException("Schema validation error", exception);
            }
            finally
            {
                reader.Close();
            }

            retValue = true;

            return retValue;
        }

        /// <summary>
        /// Check to see if first XMLDSIG certificate has same hashvalue as first XAdES SignatureCertificate
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckSameCertificate()
        {
            Boolean retVal = false;

            //KeyInfoX509Data keyInfoX509Data = new KeyInfoX509Data();
            //keyInfoX509Data.LoadXml(this.KeyInfo.GetXml());
            //if (keyInfoX509Data.Certificates.Count <= 0)
            //{
            //    throw new CryptographicException("Certificate not found in XMLDSIG signature while doing CheckSameCertificate()");
            //}
            //string xmldsigCertHash = Convert.ToBase64String(((X509Certificate)keyInfoX509Data.Certificates[0]).GetCertHash());

            X509Certificate xmldsigCert = new X509Certificate(System.Text.Encoding.ASCII.GetBytes(this.KeyInfo.GetXml().InnerText));
            String xmldsigCertHash = Convert.ToBase64String(xmldsigCert.GetCertHash());

            CertCollection xadesSigningCertificateCollection = this.XadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties.SigningCertificate.CertCollection;
            if (xadesSigningCertificateCollection.Count <= 0)
            {
                throw new XadesCryptographicException("Certificate not found in SigningCertificate element while doing CheckSameCertificate()");
            }
            String xadesCertHash = Convert.ToBase64String(((Cert)xadesSigningCertificateCollection[0]).CertDigest.DigestValue);

            if (String.Compare(xmldsigCertHash, xadesCertHash, true, CultureInfo.InvariantCulture) != 0)
            {
                throw new XadesCryptographicException("Certificate in XMLDSIG signature doesn't match certificate in SigningCertificate element");
            }
            retVal = true;

            return retVal;
        }

        /// <summary>
        /// Check if there is a HashDataInfo for each reference if there is a AllDataObjectsTimeStamp
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckAllReferencesExistInAllDataObjectsTimeStamp()
        {
            AllDataObjectsTimeStampCollection allDataObjectsTimeStampCollection;
            Boolean allHashDataInfosExist;
            TimeStamp timeStamp;
            Int32 timeStampCounter;
            Boolean retVal;

            allHashDataInfosExist = true;
            retVal = false;
            allDataObjectsTimeStampCollection = this.XadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.AllDataObjectsTimeStampCollection;
            if (allDataObjectsTimeStampCollection.Count > 0)
            {
                for (timeStampCounter = 0; allHashDataInfosExist && (timeStampCounter < allDataObjectsTimeStampCollection.Count); timeStampCounter++)
                {
                    timeStamp = allDataObjectsTimeStampCollection[timeStampCounter];
                    allHashDataInfosExist &= this.CheckHashDataInfosForTimeStamp(timeStamp);
                }
                if (!allHashDataInfosExist)
                {
                    throw new XadesCryptographicException("At least one HashDataInfo is missing in AllDataObjectsTimeStamp element");
                }
            }
            retVal = true;

            return retVal;
        }

        /// <summary>
        /// Check if the HashDataInfo of each IndividualDataObjectsTimeStamp points to existing Reference
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckAllHashDataInfosInIndividualDataObjectsTimeStamp()
        {
            IndividualDataObjectsTimeStampCollection individualDataObjectsTimeStampCollection;
            Boolean hashDataInfoExists;
            TimeStamp timeStamp;
            Int32 timeStampCounter;
            Boolean retVal;

            hashDataInfoExists = true;
            retVal = false;
            individualDataObjectsTimeStampCollection = this.XadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.IndividualDataObjectsTimeStampCollection;
            if (individualDataObjectsTimeStampCollection.Count > 0)
            {
                for (timeStampCounter = 0; hashDataInfoExists && (timeStampCounter < individualDataObjectsTimeStampCollection.Count); timeStampCounter++)
                {
                    timeStamp = individualDataObjectsTimeStampCollection[timeStampCounter];
                    hashDataInfoExists &= this.CheckHashDataInfosExist(timeStamp);
                }
                if (hashDataInfoExists == false)
                {
                    throw new XadesCryptographicException("At least one HashDataInfo is pointing to non-existing reference in IndividualDataObjectsTimeStamp element");
                }
            }
            retVal = true;

            return retVal;
        }

        /// <summary>
        /// Perform XAdES checks on contained counter signatures.  If couter signature is XMLDSIG, only XMLDSIG check (CheckSignature()) is done.
        /// </summary>
        /// <param name="counterSignatureMask">Check mask applied to counter signatures</param>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckCounterSignatures(XadesCheckSignatureMasks counterSignatureMask)
        {
            CounterSignatureCollection counterSignatureCollection;
            XadesSignedXml counterSignature;
            Boolean retVal;

            retVal = true;
            counterSignatureCollection = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection;
            for (Int32 counterSignatureCounter = 0; (retVal == true) && (counterSignatureCounter < counterSignatureCollection.Count); counterSignatureCounter++)
            {
                counterSignature = counterSignatureCollection[counterSignatureCounter];
                //TODO: check if parent signature document is present in counterSignature (maybe a deep copy is required)
                if (counterSignature.signatureStandard == KnownSignatureStandard.Xades)
                {
                    retVal &= counterSignature.XadesCheckSignature(counterSignatureMask);
                }
                else
                {
                    retVal &= counterSignature.CheckSignature();
                }
            }
            if (retVal == false)
            {
                throw new XadesCryptographicException("XadesCheckSignature() failed on at least one counter signature");
            }
            retVal = true;

            return retVal;
        }

        /// <summary>
        /// Counter signatures should all contain a reference to the parent signature SignatureValue element
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckCounterSignaturesReference()
        {
            CounterSignatureCollection counterSignatureCollection;
            XadesSignedXml counterSignature;
            String referenceUri;
            ArrayList parentSignatureValueChain;
            Boolean referenceToParentSignatureFound;
            Boolean retVal;

            retVal = true;
            parentSignatureValueChain = new ArrayList();
            parentSignatureValueChain.Add("#" + this.signatureValueId);
            counterSignatureCollection = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection;
            for (Int32 counterSignatureCounter = 0; (retVal == true) && (counterSignatureCounter < counterSignatureCollection.Count); counterSignatureCounter++)
            {
                counterSignature = counterSignatureCollection[counterSignatureCounter];
                referenceToParentSignatureFound = false;
                for (Int32 referenceCounter = 0; referenceToParentSignatureFound == false && (referenceCounter < counterSignature.SignedInfo.References.Count); referenceCounter++)
                {
                    referenceUri = ((Reference)counterSignature.SignedInfo.References[referenceCounter]).Uri;
                    if (parentSignatureValueChain.BinarySearch(referenceUri) >= 0)
                    {
                        referenceToParentSignatureFound = true;
                    }
                    parentSignatureValueChain.Add("#" + counterSignature.SignatureValueId);
                    parentSignatureValueChain.Sort();
                }
                retVal = referenceToParentSignatureFound;
            }
            if (retVal == false)
            {
                throw new XadesCryptographicException("CheckCounterSignaturesReference() failed on at least one counter signature");
            }
            retVal = true;

            return retVal;
        }

        /// <summary>
        /// Check if each ObjectReference in CommitmentTypeIndication points to Reference element
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckObjectReferencesInCommitmentTypeIndication()
        {
            CommitmentTypeIndicationCollection commitmentTypeIndicationCollection;
            CommitmentTypeIndication commitmentTypeIndication;
            Boolean objectReferenceOK;
            Boolean retVal;

            retVal = true;
            commitmentTypeIndicationCollection = this.XadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.CommitmentTypeIndicationCollection;
            if (commitmentTypeIndicationCollection.Count > 0)
            {
                for (Int32 commitmentTypeIndicationCounter = 0; (retVal == true) && (commitmentTypeIndicationCounter < commitmentTypeIndicationCollection.Count); commitmentTypeIndicationCounter++)
                {
                    commitmentTypeIndication = commitmentTypeIndicationCollection[commitmentTypeIndicationCounter];
                    objectReferenceOK = true;
                    foreach (ObjectReference objectReference in commitmentTypeIndication.ObjectReferenceCollection)
                    {
                        objectReferenceOK &= this.CheckObjectReference(objectReference);
                    }
                    retVal = objectReferenceOK;
                }
                if (retVal == false)
                {
                    throw new XadesCryptographicException("At least one ObjectReference in CommitmentTypeIndication did not point to a Reference");
                }
            }

            return retVal;
        }

        /// <summary>
        /// Check if at least ClaimedRoles or CertifiedRoles present in SignerRole
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckIfClaimedRolesOrCertifiedRolesPresentInSignerRole()
        {
            SignerRole signerRole;
            Boolean retVal;

            retVal = false;
            signerRole = this.XadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties.SignerRole;
            if (signerRole != null)
            {
                if (signerRole.CertifiedRoles != null)
                {
                    retVal = (signerRole.CertifiedRoles.CertifiedRoleCollection.Count > 0);
                }
                if (retVal == false)
                {
                    if (signerRole.ClaimedRoles != null)
                    {
                        retVal = (signerRole.ClaimedRoles.ClaimedRoleCollection.Count > 0);
                    }
                }
                if (retVal == false)
                {
                    throw new XadesCryptographicException("SignerRole element must contain at least one CertifiedRole or ClaimedRole element");
                }
            }
            else
            {
                retVal = true;
            }

            return retVal;
        }

        /// <summary>
        /// Check if HashDataInfo of SignatureTimeStamp points to SignatureValue
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckHashDataInfoOfSignatureTimeStampPointsToSignatureValue()
        {
            SignatureTimeStampCollection signatureTimeStampCollection;
            Boolean hashDataInfoPointsToSignatureValue;
            TimeStamp timeStamp;
            Int32 timeStampCounter;
            Boolean retVal;

            hashDataInfoPointsToSignatureValue = true;
            retVal = false;
            signatureTimeStampCollection = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection;
            if (signatureTimeStampCollection.Count > 0)
            {
                for (timeStampCounter = 0; hashDataInfoPointsToSignatureValue && (timeStampCounter < signatureTimeStampCollection.Count); timeStampCounter++)
                {
                    timeStamp = signatureTimeStampCollection[timeStampCounter];
                    hashDataInfoPointsToSignatureValue &= this.CheckHashDataInfoPointsToSignatureValue(timeStamp);
                }
                if (hashDataInfoPointsToSignatureValue == false)
                {
                    throw new XadesCryptographicException("HashDataInfo of SignatureTimeStamp doesn't point to signature value element");
                }
            }
            retVal = true;

            return retVal;
        }

        /// <summary>
        /// Check if the QualifyingProperties Target attribute points to the signature element
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckQualifyingPropertiesTarget()
        {
            String qualifyingPropertiesTarget;
            Boolean retVal;

            retVal = true;
            qualifyingPropertiesTarget = this.XadesObject.QualifyingProperties.Target;
            if (this.Signature.Id == null)
            {
                retVal = false;
            }
            else
            {
                if (qualifyingPropertiesTarget != ("#" + this.Signature.Id))
                {
                    retVal = false;
                }
            }
            if (retVal == false)
            {
                throw new XadesCryptographicException("Qualifying properties target doesn't point to signature element or signature element doesn't have an Id");
            }

            return retVal;
        }

        /// <summary>
        /// Check that QualifyingProperties occur in one Object, check that there is only one QualifyingProperties and that signed properties occur in one QualifyingProperties element
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckQualifyingProperties()
        {
            XmlElement signatureElement;
            XmlNamespaceManager xmlNamespaceManager;
            XmlNodeList xmlNodeList;

            signatureElement = this.GetXml();
            xmlNamespaceManager = new XmlNamespaceManager(signatureElement.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);
            xmlNodeList = signatureElement.SelectNodes("ds:Object/xsd:QualifyingProperties", xmlNamespaceManager);
            if (xmlNodeList.Count > 1)
            {
                throw new XadesCryptographicException("More than one Object contains a QualifyingProperties element");
            }

            return true;
        }

        /// <summary>
        /// Check if all required HashDataInfos are present on SigAndRefsTimeStamp
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckSigAndRefsTimeStampHashDataInfos()
        {
            SignatureTimeStampCollection signatureTimeStampCollection;
            TimeStamp timeStamp;
            Boolean allRequiredhashDataInfosFound;
            Boolean retVal;

            retVal = true;
            signatureTimeStampCollection = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.SigAndRefsTimeStampCollection;
            if (signatureTimeStampCollection.Count > 0)
            {
                allRequiredhashDataInfosFound = true;
                for (Int32 timeStampCounter = 0; allRequiredhashDataInfosFound && (timeStampCounter < signatureTimeStampCollection.Count); timeStampCounter++)
                {
                    timeStamp = signatureTimeStampCollection[timeStampCounter];
                    allRequiredhashDataInfosFound &= this.CheckHashDataInfosOfSigAndRefsTimeStamp(timeStamp);
                }
                if (allRequiredhashDataInfosFound == false)
                {
                    throw new XadesCryptographicException("At least one required HashDataInfo is missing in a SigAndRefsTimeStamp element");
                }
            }

            return retVal;
        }

        /// <summary>
        /// Check if all required HashDataInfos are present on RefsOnlyTimeStamp
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckRefsOnlyTimeStampHashDataInfos()
        {
            SignatureTimeStampCollection signatureTimeStampCollection;
            TimeStamp timeStamp;
            Boolean allRequiredhashDataInfosFound;
            Boolean retVal;

            retVal = true;
            signatureTimeStampCollection = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampCollection;
            if (signatureTimeStampCollection.Count > 0)
            {
                allRequiredhashDataInfosFound = true;
                for (Int32 timeStampCounter = 0; allRequiredhashDataInfosFound && (timeStampCounter < signatureTimeStampCollection.Count); timeStampCounter++)
                {
                    timeStamp = signatureTimeStampCollection[timeStampCounter];
                    allRequiredhashDataInfosFound &= this.CheckHashDataInfosOfRefsOnlyTimeStamp(timeStamp);
                }
                if (allRequiredhashDataInfosFound == false)
                {
                    throw new XadesCryptographicException("At least one required HashDataInfo is missing in a RefsOnlyTimeStamp element");
                }
            }

            return retVal;
        }

        /// <summary>
        /// Check if all required HashDataInfos are present on ArchiveTimeStamp
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckArchiveTimeStampHashDataInfos()
        {
            SignatureTimeStampCollection signatureTimeStampCollection;
            TimeStamp timeStamp;
            Boolean allRequiredhashDataInfosFound;
            Boolean retVal;

            retVal = true;
            signatureTimeStampCollection = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.ArchiveTimeStampCollection;
            if (signatureTimeStampCollection.Count > 0)
            {
                allRequiredhashDataInfosFound = true;
                for (Int32 timeStampCounter = 0; allRequiredhashDataInfosFound && (timeStampCounter < signatureTimeStampCollection.Count); timeStampCounter++)
                {
                    timeStamp = signatureTimeStampCollection[timeStampCounter];
                    allRequiredhashDataInfosFound &= this.CheckHashDataInfosOfArchiveTimeStamp(timeStamp);
                }
                if (allRequiredhashDataInfosFound == false)
                {
                    throw new XadesCryptographicException("At least one required HashDataInfo is missing in a ArchiveTimeStamp element");
                }
            }

            return retVal;
        }

        /// <summary>
        /// Check if a XAdES-C signature is also a XAdES-T signature
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckXadesCIsXadesT()
        {
            UnsignedSignatureProperties unsignedSignatureProperties;
            Boolean retVal;

            retVal = true;
            unsignedSignatureProperties = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
            if (((unsignedSignatureProperties.CompleteCertificateRefs != null) && (unsignedSignatureProperties.CompleteCertificateRefs.HasChanged()))
                || ((unsignedSignatureProperties.CompleteCertificateRefs != null) && (unsignedSignatureProperties.CompleteCertificateRefs.HasChanged())))
            {
                if (unsignedSignatureProperties.SignatureTimeStampCollection.Count == 0)
                {
                    throw new XadesCryptographicException("XAdES-C signature should also contain a SignatureTimeStamp element");
                }
            }

            return retVal;
        }

        /// <summary>
        /// Check if a XAdES-XL signature is also a XAdES-X signature
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckXadesXLIsXadesX()
        {
            UnsignedSignatureProperties unsignedSignatureProperties;
            Boolean retVal;

            retVal = true;
            unsignedSignatureProperties = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
            if (((unsignedSignatureProperties.CertificateValues != null) && (unsignedSignatureProperties.CertificateValues.HasChanged()))
                || ((unsignedSignatureProperties.RevocationValues != null) && (unsignedSignatureProperties.RevocationValues.HasChanged())))
            {
                if ((unsignedSignatureProperties.SigAndRefsTimeStampCollection.Count == 0) && (unsignedSignatureProperties.RefsOnlyTimeStampCollection.Count == 0))
                {
                    throw new XadesCryptographicException("XAdES-XL signature should also contain a XAdES-X element");
                }
            }

            return retVal;
        }

        /// <summary>
        /// Check if CertificateValues match CertificateRefs
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckCertificateValuesMatchCertificateRefs(String digestUrl)
        {
            UnsignedSignatureProperties unsignedSignatureProperties;
            ArrayList certDigests;
            Byte[] certDigest;
            Int32 index;
            Boolean retVal;

            //TODO: Similar test should be done for XML based (Other) certificates, but as the check needed is not known, there is no implementation
            retVal = true;
            unsignedSignatureProperties = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
            if ((unsignedSignatureProperties.CompleteCertificateRefs != null) && (unsignedSignatureProperties.CompleteCertificateRefs.CertRefs != null) &&
                (unsignedSignatureProperties.CertificateValues != null))
            {
                certDigests = new ArrayList();
                foreach (Cert cert in unsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection)
                {
                    certDigests.Add(Convert.ToBase64String(cert.CertDigest.DigestValue));
                }
                certDigests.Sort();
                foreach (EncapsulatedX509Certificate encapsulatedX509Certificate in unsignedSignatureProperties.CertificateValues.EncapsulatedX509CertificateCollection)
                {
                    DerObjectIdentifier digestOid = CryptoExtensions.GetDerOid(digestUrl);
                    certDigest = DigestUtilities.CalculateDigest(digestOid, encapsulatedX509Certificate.PkiData);
                    index = certDigests.BinarySearch(Convert.ToBase64String(certDigest));
                    if (index >= 0)
                    {
                        certDigests.RemoveAt(index);
                    }
                }
                if (certDigests.Count != 0)
                {
                    throw new XadesCryptographicException("Not all CertificateRefs correspond to CertificateValues");
                }
            }


            return retVal;
        }

        /// <summary>
        /// Check if RevocationValues match RevocationRefs
        /// </summary>
        /// <returns>If the function returns true the check was OK</returns>
        public virtual Boolean CheckRevocationValuesMatchRevocationRefs(String digestUrl)
        {
            UnsignedSignatureProperties unsignedSignatureProperties;
            ArrayList crlDigests;
            Byte[] crlDigest;
            Int32 index;
            Boolean retVal;

            //TODO: Similar test should be done for XML based (Other) revocation information and OCSP responses, but to keep the library independent of these technologies, this test is left to appliactions using the library
            retVal = true;
            unsignedSignatureProperties = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
            if ((unsignedSignatureProperties.CompleteRevocationRefs != null) && (unsignedSignatureProperties.CompleteRevocationRefs.CRLRefs != null) &&
                (unsignedSignatureProperties.RevocationValues != null))
            {
                crlDigests = new ArrayList();
                foreach (CRLRef crlRef in unsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection)
                {
                    crlDigests.Add(Convert.ToBase64String(crlRef.CertDigest.DigestValue));
                }
                crlDigests.Sort();
                foreach (CRLValue crlValue in unsignedSignatureProperties.RevocationValues.CRLValues.CRLValueCollection)
                {
                    DerObjectIdentifier digestOid = CryptoExtensions.GetDerOid(digestUrl);
                    crlDigest = DigestUtilities.CalculateDigest(digestOid, crlValue.PkiData);
                    index = crlDigests.BinarySearch(Convert.ToBase64String(crlDigest));
                    if (index >= 0)
                    {
                        crlDigests.RemoveAt(index);
                    }
                }
                if (crlDigests.Count != 0)
                {
                    throw new XadesCryptographicException("Not all RevocationRefs correspond to RevocationValues");
                }
            }

            return retVal;
        }
        #endregion

        #endregion

        #region Fix to add a namespace prefix for all XmlDsig nodes

        //jbonilla
        private void SetPrefixes(XmlNode node)
        {
            this.SetPrefix("ds", node, SignedXml.XmlDsigNamespaceUrl);
            this.SetPrefix("xades", node, XadesSignedXml.XadesNamespaceUri);
        }

        private void SetPrefix(String prefix, XmlNode node, String namespaceUrl)
        {
            if (node.NamespaceURI == namespaceUrl)
            {
                node.Prefix = prefix;
            }

            foreach (XmlNode child in node.ChildNodes)
            {
                this.SetPrefix(prefix, child, namespaceUrl);
            }

            return;
        }
        public new void ComputeSignature()
        {
            this.ComputeSignature(SignedXml.XmlDsigSHA1Url);
        }

        /// <summary>
        /// Copy of Org.BouncyCastle.Crypto.Xml.SignedXml.ComputeSignature() which will end up calling
        /// our own GetC14NDigest with a namespace prefix for all XmlDsig nodes
        /// </summary>
        public void ComputeSignature(String digestAlgorithmUrl)
        {
            this.BuildDigestedReferences();

            // Load the key
            AsymmetricKeyParameter signingKey = this.SigningKey;

            if (signingKey == null)
            {
                throw new XadesCryptographicException("Cryptography_Xml_LoadKeyFailed");
            }

            // Check the signature algorithm associated with the key so that we can accordingly set the signature method
            if (this.SignedInfo.SignatureMethod == null)
            {
                if (signingKey is ECPrivateKeyParameters)
                {
                    switch (digestAlgorithmUrl)
                    {
                        case SignedXml.XmlDsigSHA1Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA1Url;
                            break;
                        case SignedXml.XmlDsigMoreSHA224Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA224Url;
                            break;
                        case EncryptedXml.XmlEncSHA256Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA256Url;
                            break;
                        case SignedXml.XmlDsigMoreSHA384Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA384Url;
                            break;
                        case EncryptedXml.XmlEncSHA512Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA512Url;
                            break;
                        default:
                            throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for EC key not supported!");
                    }
                }
                else if (signingKey is RsaKeyParameters)
                {

                    switch (digestAlgorithmUrl)
                    {
                        case SignedXml.XmlDsigSHA1Url:
                            this.SignedInfo.SignatureMethod = XmlDsigRSASHA1Url;
                            break;
                        case SignedXml.XmlDsigMoreSHA224Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreRSASHA224Url;
                            break;
                        case EncryptedXml.XmlEncSHA256Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreRSASHA256Url;
                            break;
                        case SignedXml.XmlDsigMoreSHA384Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreRSASHA384Url;
                            break;
                        case EncryptedXml.XmlEncSHA512Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreRSASHA512Url;
                            break;
                        default:
                            throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for RSA key not supported!");
                    }
                }
                else if (signingKey is DsaKeyParameters)
                {

                    switch (digestAlgorithmUrl)
                    {
                        case SignedXml.XmlDsigSHA1Url:
                            this.SignedInfo.SignatureMethod = XmlDsigDSAUrl;
                            break;
                        case EncryptedXml.XmlEncSHA256Url:
                            this.SignedInfo.SignatureMethod = XmlDsig11DSASHA256Url;
                            break;
                        default:
                            throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for DSA key not supported!");
                    }
                }
                else
                {
                    throw new XadesCryptographicException("Cryptography_Xml_CreatedKeyFailed");
                }
            }
            // See if there is a signature description class defined in the Config file
            ISigner description = CryptoHelpers.CreateFromName<ISigner>(this.SignedInfo.SignatureMethod);
            if (description == null)
            {
                throw new XadesCryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
            }
            // In BouncyCastle we don't need to initialize a HashAlgorithm, because ISigner contains one.
            /*            
            HashAlgorithm hash = description.CreateDigest();
            if (hash == null)
            {
                throw new XadesCryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
            }
            */
            //this.GetC14NDigest(hash);
            description.Init(true, signingKey);
            this.GetC14NDigest(new SignerHashWrapper(description), "ds");
            //
            //this.m_signature.SignatureValue = description.CreateFormatter(signingKey).CreateSignature(hash);
            this.m_signature.SignatureValue = description.GenerateSignature();
        }

        //jbonilla
        /// <summary>
        /// Creates the C14N digest bytes in order to be signed.
        /// </summary>
        /// <returns>C14N digest</returns>
        public Stream PreComputeSignature()
        {
            this.BuildDigestedReferences();
            return this.GetC14NStream();
        }

        //jbonilla
        /// <summary>
        /// Adds the external generated signature.
        /// </summary>
        /// <param name="signatureValue"></param>
        public void ComputeExternalSignature(Byte[] signatureValue, String digestAlgorithmUrl)
        {
            this.BuildDigestedReferences();
            AsymmetricKeyParameter signingKey = this.SigningKey;
            if (signingKey == null)
            {
                throw new XadesCryptographicException("Cryptography_Xml_LoadKeyFailed");
            }

            // Check the signature algorithm associated with the key so that we can accordingly set the signature method
            if (this.SignedInfo.SignatureMethod == null)
            {
                if (signingKey is ECPrivateKeyParameters)
                {
                    switch (digestAlgorithmUrl)
                    {
                        case SignedXml.XmlDsigSHA1Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA1Url;
                            break;
                        case SignedXml.XmlDsigMoreSHA224Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA224Url;
                            break;
                        case EncryptedXml.XmlEncSHA256Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA256Url;
                            break;
                        case SignedXml.XmlDsigMoreSHA384Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA384Url;
                            break;
                        case EncryptedXml.XmlEncSHA512Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreECDSASHA512Url;
                            break;
                        default:
                            throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for EC key not supported!");
                    }
                }
                else if (signingKey is RsaKeyParameters)
                {

                    switch (digestAlgorithmUrl)
                    {
                        case SignedXml.XmlDsigSHA1Url:
                            this.SignedInfo.SignatureMethod = XmlDsigRSASHA1Url;
                            break;
                        case SignedXml.XmlDsigMoreSHA224Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreRSASHA224Url;
                            break;
                        case EncryptedXml.XmlEncSHA256Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreRSASHA256Url;
                            break;
                        case SignedXml.XmlDsigMoreSHA384Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreRSASHA384Url;
                            break;
                        case EncryptedXml.XmlEncSHA512Url:
                            this.SignedInfo.SignatureMethod = XmlDsigMoreRSASHA512Url;
                            break;
                        default:
                            throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for RSA key not supported!");
                    }
                }
                else if (signingKey is DsaKeyParameters)
                {

                    switch (digestAlgorithmUrl)
                    {
                        case SignedXml.XmlDsigSHA1Url:
                            this.SignedInfo.SignatureMethod = XmlDsigDSAUrl;
                            break;
                        case EncryptedXml.XmlEncSHA256Url:
                            this.SignedInfo.SignatureMethod = XmlDsig11DSASHA256Url;
                            break;
                        default:
                            throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for DSA key not supported!");
                    }
                }
                else
                {
                    throw new XadesCryptographicException("Cryptography_Xml_CreatedKeyFailed");
                }
            }
            // See if there is a signature description class defined in the Config file
            ISigner description = CryptoHelpers.CreateFromName<ISigner>(this.SignedInfo.SignatureMethod);
            if (description == null)
            {
                throw new XadesCryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
            }
            // In BouncyCastle we don't need to initialize a HashAlgorithm, because ISigner contains one.
            /*            
            HashAlgorithm hash = description.CreateDigest();
            if (hash == null)
            {
                throw new XadesCryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
            }
            */
            //this.GetC14NDigest(hash);
            description.Init(true, signingKey);
            this.GetC14NDigest(new SignerHashWrapper(description), "ds");
            //
            //this.m_signature.SignatureValue = description.CreateFormatter(signingKey).CreateSignature(hash);
            //
            this.m_signature.SignatureValue = signatureValue;
        }

        /// <summary>
        /// Copy of Org.BouncyCastle.Crypto.Xml.SignedXml.BuildDigestedReferences() which will add a "ds" 
        /// namespace prefix to all XmlDsig nodes
        /// </summary>
        private void BuildDigestedReferences()
        {
            ArrayList references = this.SignedInfo.References;

            //this.m_refProcessed = new bool[references.Count];
            Type SignedXml_Type = typeof(SignedXml);
            FieldInfo SignedXml_m_refProcessed = SignedXml_Type.GetField("m_refProcessed", BindingFlags.NonPublic | BindingFlags.Instance);
            SignedXml_m_refProcessed.SetValue(this, new Boolean[references.Count]);
            //            

            //this.m_refLevelCache = new int[references.Count];
            FieldInfo SignedXml_m_refLevelCache = SignedXml_Type.GetField("m_refLevelCache", BindingFlags.NonPublic | BindingFlags.Instance);
            SignedXml_m_refLevelCache.SetValue(this, new Int32[references.Count]);
            //            

            //ReferenceLevelSortOrder comparer = new ReferenceLevelSortOrder();
            Assembly System_Security_Assembly = Assembly.Load("System.Security, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
            Type ReferenceLevelSortOrder_Type = System_Security_Assembly.GetType("Org.BouncyCastle.Crypto.Xml.SignedXml+ReferenceLevelSortOrder");
            ConstructorInfo ReferenceLevelSortOrder_Constructor = ReferenceLevelSortOrder_Type.GetConstructor(new Type[] { });
            Object comparer = ReferenceLevelSortOrder_Constructor.Invoke(null);
            //

            //comparer.References = references;
            PropertyInfo ReferenceLevelSortOrder_References = ReferenceLevelSortOrder_Type.GetProperty("References", BindingFlags.Public | BindingFlags.Instance);
            ReferenceLevelSortOrder_References.SetValue(comparer, references, null);
            //

            ArrayList list2 = new ArrayList();
            foreach (Reference reference in references)
            {
                list2.Add(reference);
            }

            list2.Sort((IComparer)comparer);

            //CanonicalXmlNodeList refList = new CanonicalXmlNodeList();
            Type CanonicalXmlNodeList_Type = System_Security_Assembly.GetType("Org.BouncyCastle.Crypto.Xml.CanonicalXmlNodeList");
            ConstructorInfo CanonicalXmlNodeList_Constructor = CanonicalXmlNodeList_Type.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { }, null);
            Object refList = CanonicalXmlNodeList_Constructor.Invoke(null);
            //

            //
            MethodInfo CanonicalXmlNodeList_Add = CanonicalXmlNodeList_Type.GetMethod("Add", BindingFlags.Public | BindingFlags.Instance);
            //

            foreach (DataObject obj2 in this.m_signature.ObjectList)
            {
                //refList.Add(obj2.GetXml());
                XmlElement xml = obj2.GetXml();
                //SetPrefix("ds", xml, SignedXml.XmlDsigNamespaceUrl); // <---
                this.SetPrefixes(xml);
                CanonicalXmlNodeList_Add.Invoke(refList, new Object[] { xml });
                //
            }

            //
            FieldInfo SignedXml_m_containingDocument = SignedXml_Type.GetField("m_containingDocument", BindingFlags.NonPublic | BindingFlags.Instance);
            Type Reference_Type = typeof(Reference);
            MethodInfo Reference_UpdateHashValue = Reference_Type.GetMethod("UpdateHashValue", BindingFlags.NonPublic | BindingFlags.Instance);
            //

            foreach (Reference reference2 in list2)
            {
                if (reference2.DigestMethod == null)
                {
                    reference2.DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
                }
                //reference2.UpdateHashValue(this.m_containingDocument, refList);
                Object m_containingDocument = SignedXml_m_containingDocument.GetValue(this);
                Reference_UpdateHashValue.Invoke(reference2, new Object[] { m_containingDocument, refList });
                // 

                if (reference2.Id != null)
                {
                    //refList.Add(reference2.GetXml());
                    XmlElement xml = reference2.GetXml();
                    //SetPrefix("ds", xml, SignedXml.XmlDsigNamespaceUrl); // <---
                    this.SetPrefixes(xml); // <---
                    CanonicalXmlNodeList_Add.Invoke(refList, new Object[] { xml });
                    //
                }
            }

        }

        /// <summary>
        /// We won't call Org.BouncyCastle.Crypto.Xml.SignedXml.GetC14NDigest(), as we want to use our own.
        /// </summary>
        private Byte[] GetC14NDigest(IHash hash)
        {
            return null;
        }

        /// <summary>
        /// Copy of Org.BouncyCastle.Crypto.Xml.SignedXml.GetC14NDigest() which will add a
        /// namespace prefix to all XmlDsig nodes
        /// </summary>
        private Byte[] GetC14NDigest(IHash hash, String prefix)
        {
            //if (!this.bCacheValid || !this.SignedInfo.CacheValid)
            //{
            Type SignedXml_Type = typeof(SignedXml);
            FieldInfo SignedXml_bCacheValid = SignedXml_Type.GetField("bCacheValid", BindingFlags.NonPublic | BindingFlags.Instance);
            Boolean bCacheValid = (Boolean)SignedXml_bCacheValid.GetValue(this);
            Type SignedInfo_Type = typeof(SignedInfo);
            PropertyInfo SignedInfo_CacheValid = SignedInfo_Type.GetProperty("CacheValid", BindingFlags.NonPublic | BindingFlags.Instance);
            Boolean CacheValid = (Boolean)SignedInfo_CacheValid.GetValue(this.SignedInfo, null);

            FieldInfo SignedXml__digestedSignedInfo = SignedXml_Type.GetField("_digestedSignedInfo", BindingFlags.NonPublic | BindingFlags.Instance);

            if (!bCacheValid || !CacheValid)
            {
                //
                //string securityUrl = (this.m_containingDocument == null) ? null : this.m_containingDocument.BaseURI;
                FieldInfo SignedXml_m_containingDocument = SignedXml_Type.GetField("m_containingDocument", BindingFlags.NonPublic | BindingFlags.Instance);
                XmlDocument m_containingDocument = (XmlDocument)SignedXml_m_containingDocument.GetValue(this);
                String securityUrl = (m_containingDocument == null) ? null : m_containingDocument.BaseURI;
                //

                //XmlResolver xmlResolver = this.m_bResolverSet ? this.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), securityUrl);
                FieldInfo SignedXml_m_bResolverSet = SignedXml_Type.GetField("m_bResolverSet", BindingFlags.NonPublic | BindingFlags.Instance);
                Boolean m_bResolverSet = (Boolean)SignedXml_m_bResolverSet.GetValue(this);
                FieldInfo SignedXml_m_xmlResolver = SignedXml_Type.GetField("m_xmlResolver", BindingFlags.NonPublic | BindingFlags.Instance);
                XmlResolver m_xmlResolver = (XmlResolver)SignedXml_m_xmlResolver.GetValue(this);
                XmlResolver xmlResolver = m_bResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), securityUrl);
                //

                //XmlDocument document = Utils.PreProcessElementInput(this.SignedInfo.GetXml(), xmlResolver, securityUrl);
                Assembly System_Security_Assembly = Assembly.Load("System.Security, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
                Type Utils_Type = System_Security_Assembly.GetType("Org.BouncyCastle.Crypto.Xml.Utils");
                MethodInfo Utils_PreProcessElementInput = Utils_Type.GetMethod("PreProcessElementInput", BindingFlags.NonPublic | BindingFlags.Static);
                XmlElement xml = this.SignedInfo.GetXml();
                //SetPrefix(prefix, xml, SignedXml.XmlDsigNamespaceUrl); // <---
                this.SetPrefixes(xml); // <---
                XmlDocument document = (XmlDocument)Utils_PreProcessElementInput.Invoke(null, new Object[] { xml, xmlResolver, securityUrl });
                //

                //CanonicalXmlNodeList namespaces = (this.m_context == null) ? null : Utils.GetPropagatedAttributes(this.m_context);
                FieldInfo SignedXml_m_context = SignedXml_Type.GetField("m_context", BindingFlags.NonPublic | BindingFlags.Instance);
                MethodInfo Utils_GetPropagatedAttributes = Utils_Type.GetMethod("GetPropagatedAttributes", BindingFlags.NonPublic | BindingFlags.Static);
                Object m_context = SignedXml_m_context.GetValue(this);
                Object namespaces = (m_context == null) ? null : Utils_GetPropagatedAttributes.Invoke(null, new Object[] { m_context });
                //

                // Utils.AddNamespaces(document.DocumentElement, namespaces);
                Type CanonicalXmlNodeList_Type = System_Security_Assembly.GetType("Org.BouncyCastle.Crypto.Xml.CanonicalXmlNodeList");
                MethodInfo Utils_AddNamespaces = Utils_Type.GetMethod("AddNamespaces", BindingFlags.NonPublic | BindingFlags.Static, null, new Type[] { typeof(XmlElement), CanonicalXmlNodeList_Type }, null);
                Utils_AddNamespaces.Invoke(null, new Object[] { document.DocumentElement, namespaces });
                //

                //Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
                Org.BouncyCastle.Crypto.Xml.Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
                //

                canonicalizationMethodObject.Resolver = xmlResolver;

                //canonicalizationMethodObject.BaseURI = securityUrl;
                Type Transform_Type = typeof(Org.BouncyCastle.Crypto.Xml.Transform);
                PropertyInfo Transform_BaseURI = Transform_Type.GetProperty("BaseURI", BindingFlags.NonPublic | BindingFlags.Instance);
                Transform_BaseURI.SetValue(canonicalizationMethodObject, securityUrl, null);
                //

                canonicalizationMethodObject.LoadInput(document);

                //this._digestedSignedInfo = canonicalizationMethodObject.GetDigestedOutput(hash);
                //SignedXml__digestedSignedInfo.SetValue(this, canonicalizationMethodObject.GetDigestedOutput(hash));
                canonicalizationMethodObject.GetDigestedOutput(hash);
                //

                //this.bCacheValid = true;
                SignedXml_bCacheValid.SetValue(this, true);
                //
            }

            //return this._digestedSignedInfo;
            Byte[] _digestedSignedInfo = (Byte[])SignedXml__digestedSignedInfo.GetValue(this);
            return _digestedSignedInfo;
            //
        }

        private Stream GetC14NStream()
        {
            //if (!this.bCacheValid || !this.SignedInfo.CacheValid)
            //{
            Type SignedXml_Type = typeof(SignedXml);
            FieldInfo SignedXml_bCacheValid = SignedXml_Type.GetField("bCacheValid", BindingFlags.NonPublic | BindingFlags.Instance);
            Boolean bCacheValid = (Boolean)SignedXml_bCacheValid.GetValue(this);
            Type SignedInfo_Type = typeof(SignedInfo);
            PropertyInfo SignedInfo_CacheValid = SignedInfo_Type.GetProperty("CacheValid", BindingFlags.NonPublic | BindingFlags.Instance);
            Boolean CacheValid = (Boolean)SignedInfo_CacheValid.GetValue(this.SignedInfo, null);

            FieldInfo SignedXml__digestedSignedInfo = SignedXml_Type.GetField("_digestedSignedInfo", BindingFlags.NonPublic | BindingFlags.Instance);

            Stream _signedInfoStream = null;

            if (!bCacheValid || !CacheValid)
            {
                //
                //string securityUrl = (this.m_containingDocument == null) ? null : this.m_containingDocument.BaseURI;
                FieldInfo SignedXml_m_containingDocument = SignedXml_Type.GetField("m_containingDocument", BindingFlags.NonPublic | BindingFlags.Instance);
                XmlDocument m_containingDocument = (XmlDocument)SignedXml_m_containingDocument.GetValue(this);
                String securityUrl = (m_containingDocument == null) ? null : m_containingDocument.BaseURI;
                //

                //XmlResolver xmlResolver = this.m_bResolverSet ? this.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), securityUrl);
                FieldInfo SignedXml_m_bResolverSet = SignedXml_Type.GetField("m_bResolverSet", BindingFlags.NonPublic | BindingFlags.Instance);
                Boolean m_bResolverSet = (Boolean)SignedXml_m_bResolverSet.GetValue(this);
                FieldInfo SignedXml_m_xmlResolver = SignedXml_Type.GetField("m_xmlResolver", BindingFlags.NonPublic | BindingFlags.Instance);
                XmlResolver m_xmlResolver = (XmlResolver)SignedXml_m_xmlResolver.GetValue(this);
                XmlResolver xmlResolver = m_bResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), securityUrl);
                //

                //XmlDocument document = Utils.PreProcessElementInput(this.SignedInfo.GetXml(), xmlResolver, securityUrl);
                Assembly System_Security_Assembly = Assembly.Load("System.Security, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
                Type Utils_Type = System_Security_Assembly.GetType("Org.BouncyCastle.Crypto.Xml.Utils");
                MethodInfo Utils_PreProcessElementInput = Utils_Type.GetMethod("PreProcessElementInput", BindingFlags.NonPublic | BindingFlags.Static);
                XmlElement xml = this.SignedInfo.GetXml();
                //SetPrefix(prefix, xml, SignedXml.XmlDsigNamespaceUrl); // <---
                this.SetPrefixes(xml); // <---
                XmlDocument document = (XmlDocument)Utils_PreProcessElementInput.Invoke(null, new Object[] { xml, xmlResolver, securityUrl });
                //

                //CanonicalXmlNodeList namespaces = (this.m_context == null) ? null : Utils.GetPropagatedAttributes(this.m_context);
                FieldInfo SignedXml_m_context = SignedXml_Type.GetField("m_context", BindingFlags.NonPublic | BindingFlags.Instance);
                MethodInfo Utils_GetPropagatedAttributes = Utils_Type.GetMethod("GetPropagatedAttributes", BindingFlags.NonPublic | BindingFlags.Static);
                Object m_context = SignedXml_m_context.GetValue(this);
                Object namespaces = (m_context == null) ? null : Utils_GetPropagatedAttributes.Invoke(null, new Object[] { m_context });
                //

                // Utils.AddNamespaces(document.DocumentElement, namespaces);
                Type CanonicalXmlNodeList_Type = System_Security_Assembly.GetType("Org.BouncyCastle.Crypto.Xml.CanonicalXmlNodeList");
                MethodInfo Utils_AddNamespaces = Utils_Type.GetMethod("AddNamespaces", BindingFlags.NonPublic | BindingFlags.Static, null, new Type[] { typeof(XmlElement), CanonicalXmlNodeList_Type }, null);
                Utils_AddNamespaces.Invoke(null, new Object[] { document.DocumentElement, namespaces });
                //

                //Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
                //Org.BouncyCastle.Crypto.Xml.Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
                //jbonilla - Hack para que funcione con Mono
                Org.BouncyCastle.Crypto.Xml.Transform canonicalizationMethodObject = CryptoHelpers.CreateFromName<Org.BouncyCastle.Crypto.Xml.Transform>(this.SignedInfo.CanonicalizationMethod);
                //

                canonicalizationMethodObject.Resolver = xmlResolver;

                //canonicalizationMethodObject.BaseURI = securityUrl;
                Type Transform_Type = typeof(Org.BouncyCastle.Crypto.Xml.Transform);
                PropertyInfo Transform_BaseURI = Transform_Type.GetProperty("BaseURI", BindingFlags.NonPublic | BindingFlags.Instance);
                Transform_BaseURI.SetValue(canonicalizationMethodObject, securityUrl, null);
                //

                canonicalizationMethodObject.LoadInput(document);

                _signedInfoStream = (Stream)canonicalizationMethodObject.GetOutput();
                //
            }

            return _signedInfoStream;
        }

        #endregion

        #region Private methods

        private XmlElement GetXadesObjectElement(XmlElement signatureElement)
        {
            XmlElement retVal = null;

            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(signatureElement.OwnerDocument.NameTable); //Create an XmlNamespaceManager to resolve namespace
            xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

            XmlNodeList xmlNodeList = signatureElement.SelectNodes("ds:Object/xsd:QualifyingProperties", xmlNamespaceManager);
            if (xmlNodeList.Count > 0)
            {
                retVal = (XmlElement)xmlNodeList.Item(0).ParentNode;
            }
            else
            {
                retVal = null;
            }

            return retVal;
        }

        private void SetSignatureStandard(XmlElement signatureElement)
        {
            if (this.GetXadesObjectElement(signatureElement) != null)
            {
                this.signatureStandard = KnownSignatureStandard.Xades;
            }
            else
            {
                this.signatureStandard = KnownSignatureStandard.XmlDsig;
            }
        }

        private Org.BouncyCastle.Crypto.Xml.DataObject GetXadesDataObject()
        {
            Org.BouncyCastle.Crypto.Xml.DataObject retVal = null;

            for (Int32 dataObjectCounter = 0; dataObjectCounter < (this.Signature.ObjectList.Count); dataObjectCounter++)
            {
                Org.BouncyCastle.Crypto.Xml.DataObject dataObject = (Org.BouncyCastle.Crypto.Xml.DataObject)this.Signature.ObjectList[dataObjectCounter];
                XmlElement dataObjectXmlElement = dataObject.GetXml();
                XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(dataObjectXmlElement.OwnerDocument.NameTable);
                xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);
                XmlNodeList xmlNodeList = dataObjectXmlElement.SelectNodes("xsd:QualifyingProperties", xmlNamespaceManager);
                if (xmlNodeList.Count != 0)
                {
                    retVal = dataObject;

                    break;
                }
            }

            return retVal;
        }

        private void SchemaValidationHandler(Object sender, ValidationEventArgs validationEventArgs)
        {
            this.validationErrorOccurred = true;
            this.validationErrorDescription += "Validation error:\n";
            this.validationErrorDescription += "\tSeverity: " + validationEventArgs.Severity.ToString() + "\n";
            this.validationErrorDescription += "\tMessage: " + validationEventArgs.Message + "\n";
        }

        private void XmlValidationHandler(Object sender, ValidationEventArgs validationEventArgs)
        {
            if (validationEventArgs.Severity != XmlSeverityType.Warning)
            {
                this.validationErrorOccurred = true;
                this.validationErrorDescription += "Validation error:\n";
                this.validationErrorDescription += "\tSeverity: " + validationEventArgs.Severity.ToString() + "\n";
                this.validationErrorDescription += "\tMessage: " + validationEventArgs.Message + "\n";
            }
        }

        private Boolean CheckHashDataInfosForTimeStamp(TimeStamp timeStamp)
        {
            Boolean retVal = true;

            for (Int32 referenceCounter = 0; retVal == true && (referenceCounter < this.SignedInfo.References.Count); referenceCounter++)
            {
                String referenceId = ((Reference)this.SignedInfo.References[referenceCounter]).Id;
                String referenceUri = ((Reference)this.SignedInfo.References[referenceCounter]).Uri;
                if (referenceUri != ("#" + this.XadesObject.QualifyingProperties.SignedProperties.Id))
                {
                    Boolean hashDataInfoFound = false;
                    for (Int32 hashDataInfoCounter = 0; hashDataInfoFound == false && (hashDataInfoCounter < timeStamp.HashDataInfoCollection.Count); hashDataInfoCounter++)
                    {
                        HashDataInfo hashDataInfo = timeStamp.HashDataInfoCollection[hashDataInfoCounter];
                        hashDataInfoFound = (("#" + referenceId) == hashDataInfo.UriAttribute);
                    }
                    retVal = hashDataInfoFound;
                }
            }

            return retVal;
        }

        private Boolean CheckHashDataInfosExist(TimeStamp timeStamp)
        {
            Boolean retVal = true;

            for (Int32 hashDataInfoCounter = 0; retVal == true && (hashDataInfoCounter < timeStamp.HashDataInfoCollection.Count); hashDataInfoCounter++)
            {
                HashDataInfo hashDataInfo = timeStamp.HashDataInfoCollection[hashDataInfoCounter];
                Boolean referenceFound = false;
                String referenceId;

                for (Int32 referenceCounter = 0; referenceFound == false && (referenceCounter < this.SignedInfo.References.Count); referenceCounter++)
                {
                    referenceId = ((Reference)this.SignedInfo.References[referenceCounter]).Id;
                    if (("#" + referenceId) == hashDataInfo.UriAttribute)
                    {
                        referenceFound = true;
                    }
                }
                retVal = referenceFound;
            }

            return retVal;
        }


        private Boolean CheckObjectReference(ObjectReference objectReference)
        {
            Boolean retVal = false;

            for (Int32 referenceCounter = 0; retVal == false && (referenceCounter < this.SignedInfo.References.Count); referenceCounter++)
            {
                String referenceId = ((Reference)this.SignedInfo.References[referenceCounter]).Id;
                if (("#" + referenceId) == objectReference.ObjectReferenceUri)
                {
                    retVal = true;
                }
            }

            return retVal;
        }

        private Boolean CheckHashDataInfoPointsToSignatureValue(TimeStamp timeStamp)
        {
            Boolean retVal = true;
            foreach (HashDataInfo hashDataInfo in timeStamp.HashDataInfoCollection)
            {
                retVal &= (hashDataInfo.UriAttribute == ("#" + this.signatureValueId));
            }

            return retVal;
        }

        private Boolean CheckHashDataInfosOfSigAndRefsTimeStamp(TimeStamp timeStamp)
        {
            UnsignedSignatureProperties unsignedSignatureProperties;
            Boolean signatureValueHashDataInfoFound = false;
            Boolean allSignatureTimeStampHashDataInfosFound = false;
            Boolean completeCertificateRefsHashDataInfoFound = false;
            Boolean completeRevocationRefsHashDataInfoFound = false;

            ArrayList signatureTimeStampIds = new ArrayList();

            Boolean retVal = true;

            unsignedSignatureProperties = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;

            foreach (TimeStamp signatureTimeStamp in unsignedSignatureProperties.SignatureTimeStampCollection)
            {
                signatureTimeStampIds.Add("#" + signatureTimeStamp.EncapsulatedTimeStamp.Id);
            }
            signatureTimeStampIds.Sort();
            foreach (HashDataInfo hashDataInfo in timeStamp.HashDataInfoCollection)
            {
                if (hashDataInfo.UriAttribute == "#" + this.signatureValueId)
                {
                    signatureValueHashDataInfoFound = true;
                }
                Int32 signatureTimeStampIdIndex = signatureTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
                if (signatureTimeStampIdIndex >= 0)
                {
                    signatureTimeStampIds.RemoveAt(signatureTimeStampIdIndex);
                }
                if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CompleteCertificateRefs.Id)
                {
                    completeCertificateRefsHashDataInfoFound = true;
                }
                if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CompleteRevocationRefs.Id)
                {
                    completeRevocationRefsHashDataInfoFound = true;
                }
            }
            if (signatureTimeStampIds.Count == 0)
            {
                allSignatureTimeStampHashDataInfosFound = true;
            }
            retVal = signatureValueHashDataInfoFound && allSignatureTimeStampHashDataInfosFound && completeCertificateRefsHashDataInfoFound && completeRevocationRefsHashDataInfoFound;

            return retVal;
        }

        private Boolean CheckHashDataInfosOfRefsOnlyTimeStamp(TimeStamp timeStamp)
        {
            UnsignedSignatureProperties unsignedSignatureProperties;
            Boolean completeCertificateRefsHashDataInfoFound;
            Boolean completeRevocationRefsHashDataInfoFound;
            Boolean retVal;

            completeCertificateRefsHashDataInfoFound = false;
            completeRevocationRefsHashDataInfoFound = false;
            retVal = true;

            unsignedSignatureProperties = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
            foreach (HashDataInfo hashDataInfo in timeStamp.HashDataInfoCollection)
            {
                if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CompleteCertificateRefs.Id)
                {
                    completeCertificateRefsHashDataInfoFound = true;
                }
                if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CompleteRevocationRefs.Id)
                {
                    completeRevocationRefsHashDataInfoFound = true;
                }
            }
            retVal = completeCertificateRefsHashDataInfoFound && completeRevocationRefsHashDataInfoFound;

            return retVal;
        }

        private Boolean CheckHashDataInfosOfArchiveTimeStamp(TimeStamp timeStamp)
        {
            UnsignedSignatureProperties unsignedSignatureProperties;
            SignedProperties signedProperties;

            Boolean allReferenceHashDataInfosFound = false;
            Boolean signedInfoHashDataInfoFound = false;
            Boolean signedPropertiesHashDataInfoFound = false;
            Boolean signatureValueHashDataInfoFound = false;
            Boolean allSignatureTimeStampHashDataInfosFound = false;
            Boolean completeCertificateRefsHashDataInfoFound = false;
            Boolean completeRevocationRefsHashDataInfoFound = false;
            Boolean certificatesValuesHashDataInfoFound = false;
            Boolean revocationValuesHashDataInfoFound = false;
            Boolean allSigAndRefsTimeStampHashDataInfosFound = false;
            Boolean allRefsOnlyTimeStampHashDataInfosFound = false;
            Boolean allArchiveTimeStampHashDataInfosFound = false;
            Boolean allOlderArchiveTimeStampsFound = false;

            ArrayList referenceIds = new ArrayList();
            ArrayList signatureTimeStampIds = new ArrayList();
            ArrayList sigAndRefsTimeStampIds = new ArrayList();
            ArrayList refsOnlyTimeStampIds = new ArrayList();
            ArrayList archiveTimeStampIds = new ArrayList();

            Boolean retVal = true;

            unsignedSignatureProperties = this.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
            signedProperties = this.XadesObject.QualifyingProperties.SignedProperties;

            foreach (Reference reference in this.Signature.SignedInfo.References)
            {
                if (reference.Uri != "#" + signedProperties.Id)
                {
                    referenceIds.Add(reference.Uri);
                }
            }
            referenceIds.Sort();
            foreach (TimeStamp signatureTimeStamp in unsignedSignatureProperties.SignatureTimeStampCollection)
            {
                signatureTimeStampIds.Add("#" + signatureTimeStamp.EncapsulatedTimeStamp.Id);
            }
            signatureTimeStampIds.Sort();
            foreach (TimeStamp sigAndRefsTimeStamp in unsignedSignatureProperties.SigAndRefsTimeStampCollection)
            {
                sigAndRefsTimeStampIds.Add("#" + sigAndRefsTimeStamp.EncapsulatedTimeStamp.Id);
            }
            sigAndRefsTimeStampIds.Sort();
            foreach (TimeStamp refsOnlyTimeStamp in unsignedSignatureProperties.RefsOnlyTimeStampCollection)
            {
                refsOnlyTimeStampIds.Add("#" + refsOnlyTimeStamp.EncapsulatedTimeStamp.Id);
            }
            refsOnlyTimeStampIds.Sort();
            allOlderArchiveTimeStampsFound = false;
            for (Int32 archiveTimeStampCounter = 0; !allOlderArchiveTimeStampsFound && (archiveTimeStampCounter < unsignedSignatureProperties.ArchiveTimeStampCollection.Count); archiveTimeStampCounter++)
            {
                TimeStamp archiveTimeStamp = unsignedSignatureProperties.ArchiveTimeStampCollection[archiveTimeStampCounter];
                if (archiveTimeStamp.EncapsulatedTimeStamp.Id == timeStamp.EncapsulatedTimeStamp.Id)
                {
                    allOlderArchiveTimeStampsFound = true;
                }
                else
                {
                    archiveTimeStampIds.Add("#" + archiveTimeStamp.EncapsulatedTimeStamp.Id);
                }
            }

            archiveTimeStampIds.Sort();
            foreach (HashDataInfo hashDataInfo in timeStamp.HashDataInfoCollection)
            {
                Int32 index = referenceIds.BinarySearch(hashDataInfo.UriAttribute);
                if (index >= 0)
                {
                    referenceIds.RemoveAt(index);
                }
                if (hashDataInfo.UriAttribute == "#" + this.signedInfoIdBuffer)
                {
                    signedInfoHashDataInfoFound = true;
                }
                if (hashDataInfo.UriAttribute == "#" + signedProperties.Id)
                {
                    signedPropertiesHashDataInfoFound = true;
                }
                if (hashDataInfo.UriAttribute == "#" + this.signatureValueId)
                {
                    signatureValueHashDataInfoFound = true;
                }
                index = signatureTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
                if (index >= 0)
                {
                    signatureTimeStampIds.RemoveAt(index);
                }
                if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CompleteCertificateRefs.Id)
                {
                    completeCertificateRefsHashDataInfoFound = true;
                }
                if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CompleteRevocationRefs.Id)
                {
                    completeRevocationRefsHashDataInfoFound = true;
                }
                if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CertificateValues.Id)
                {
                    certificatesValuesHashDataInfoFound = true;
                }
                if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.RevocationValues.Id)
                {
                    revocationValuesHashDataInfoFound = true;
                }
                index = sigAndRefsTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
                if (index >= 0)
                {
                    sigAndRefsTimeStampIds.RemoveAt(index);
                }
                index = refsOnlyTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
                if (index >= 0)
                {
                    refsOnlyTimeStampIds.RemoveAt(index);
                }
                index = archiveTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
                if (index >= 0)
                {
                    archiveTimeStampIds.RemoveAt(index);
                }
            }
            if (referenceIds.Count == 0)
            {
                allReferenceHashDataInfosFound = true;
            }
            if (signatureTimeStampIds.Count == 0)
            {
                allSignatureTimeStampHashDataInfosFound = true;
            }
            if (sigAndRefsTimeStampIds.Count == 0)
            {
                allSigAndRefsTimeStampHashDataInfosFound = true;
            }
            if (refsOnlyTimeStampIds.Count == 0)
            {
                allRefsOnlyTimeStampHashDataInfosFound = true;
            }
            if (archiveTimeStampIds.Count == 0)
            {
                allArchiveTimeStampHashDataInfosFound = true;
            }

            retVal = allReferenceHashDataInfosFound && signedInfoHashDataInfoFound && signedPropertiesHashDataInfoFound &&
                signatureValueHashDataInfoFound && allSignatureTimeStampHashDataInfosFound && completeCertificateRefsHashDataInfoFound &&
                completeRevocationRefsHashDataInfoFound && certificatesValuesHashDataInfoFound && revocationValuesHashDataInfoFound &&
                allSigAndRefsTimeStampHashDataInfosFound && allRefsOnlyTimeStampHashDataInfosFound && allArchiveTimeStampHashDataInfosFound;

            return retVal;
        }
        #endregion

        #region Mono

        private new Stream SignedInfoTransformed()
        {
            Type SignedXml_Type = typeof(SignedXml);

            //Transform t = GetC14NMethod ();            
            MethodInfo SignedXml_GetC14NMethod = SignedXml_Type.GetMethod("GetC14NMethod", BindingFlags.NonPublic | BindingFlags.Instance);
            Org.BouncyCastle.Crypto.Xml.Transform t = (Org.BouncyCastle.Crypto.Xml.Transform)SignedXml_GetC14NMethod.Invoke(this, null);
            //

            //if (signatureElement == null) {
            FieldInfo SignedXml_signatureElement = SignedXml_Type.GetField("signatureElement", BindingFlags.NonPublic | BindingFlags.Instance);
            XmlElement signatureElement = (XmlElement)SignedXml_signatureElement.GetValue(this);
            if (signatureElement == null)
            {
                //
                // when creating signatures
                XmlDocument doc = new XmlDocument();
                doc.PreserveWhitespace = true;
                doc.LoadXml(this.m_signature.SignedInfo.GetXml().OuterXml);

                //if (envdoc != null)
                FieldInfo SignedXml_envdoc = SignedXml_Type.GetField("envdoc", BindingFlags.NonPublic | BindingFlags.Instance);
                XmlDocument envdoc = (XmlDocument)SignedXml_envdoc.GetValue(this);
                if (envdoc != null)
                {
                    //
                    foreach (XmlAttribute attr in envdoc.DocumentElement.SelectNodes("namespace::*"))
                    {
                        if (attr.LocalName == "xml")
                        {
                            continue;
                        }

                        if (attr.Prefix == doc.DocumentElement.Prefix)
                        {
                            continue;
                        }

                        doc.DocumentElement.SetAttributeNode(doc.ImportNode(attr, true) as XmlAttribute);
                    }
                }
                //jbonilla
                this.SetPrefixes(doc);

                t.LoadInput(doc);
            }
            else
            {
                // when verifying signatures
                // TODO - check m_signature.SignedInfo.Id
                //XmlElement el = signatureElement.GetElementsByTagName (XmlSignature.ElementNames.SignedInfo, XmlSignature.NamespaceURI) [0] as XmlElement;
                XmlElement el = signatureElement.GetElementsByTagName("SignedInfo", "http://www.w3.org/2000/09/xmldsig#")[0] as XmlElement;
                //
                StringWriter sw = new StringWriter();
                XmlTextWriter xtw = new XmlTextWriter(sw);
                xtw.WriteStartElement(el.Prefix, el.LocalName, el.NamespaceURI);

                // context namespace nodes (except for "xmlns:xml")
                XmlNodeList nl = el.SelectNodes("namespace::*");
                foreach (XmlAttribute attr in nl)
                {
                    if (attr.ParentNode == el)
                    {
                        continue;
                    }

                    if (attr.LocalName == "xml")
                    {
                        continue;
                    }

                    if (attr.Prefix == el.Prefix)
                    {
                        continue;
                    }

                    attr.WriteTo(xtw);
                }
                foreach (XmlNode attr in el.Attributes)
                {
                    attr.WriteTo(xtw);
                }

                foreach (XmlNode n in el.ChildNodes)
                {
                    n.WriteTo(xtw);
                }

                xtw.WriteEndElement();
                Byte[] si = Encoding.UTF8.GetBytes(sw.ToString());

                MemoryStream ms = new MemoryStream();
                ms.Write(si, 0, si.Length);
                ms.Position = 0;

                t.LoadInput(ms);
            }
            // C14N and C14NWithComments always return a Stream in GetOutput
            return (Stream)t.GetOutput();
        }
        #endregion Mono
    }
}
