// DataIbjectFormat.cs
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
    /// The DataObjectFormat element provides information that describes the
    /// format of the signed data object. This element must be present when it
    /// is mandatory to present the signed data object to human users on
    /// verification.
    /// This is a signed property that qualifies one specific signed data
    /// object. In consequence, a XAdES signature may contain more than one
    /// DataObjectFormat elements, each one qualifying one signed data object.
    /// </summary>
    public class DataObjectFormat
    {
        #region Private variables
        private String objectReferenceAttribute;
        private String description;
        private ObjectIdentifier objectIdentifier;
        private String mimeType;
        private String encoding;
        #endregion

        #region Public properties
        /// <summary>
        /// The mandatory ObjectReference attribute refers to the Reference element
        /// of the signature corresponding with the data object qualified by this
        /// property.
        /// </summary>
        public String ObjectReferenceAttribute
        {
            get
            {
                return this.objectReferenceAttribute;
            }
            set
            {
                this.objectReferenceAttribute = value;
            }
        }

        /// <summary>
        /// Textual information related to the signed data object
        /// </summary>
        public String Description
        {
            get
            {
                return this.description;
            }
            set
            {
                this.description = value;
            }
        }

        /// <summary>
        /// An identifier indicating the type of the signed data object
        /// </summary>
        public ObjectIdentifier ObjectIdentifier
        {
            get
            {
                return this.objectIdentifier;
            }
            set
            {
                this.objectIdentifier = value;
            }
        }

        /// <summary>
        /// An indication of the MIME type of the signed data object
        /// </summary>
        public String MimeType
        {
            get
            {
                return this.mimeType;
            }
            set
            {
                this.mimeType = value;
            }
        }

        /// <summary>
        /// An indication of the encoding format of the signed data object
        /// </summary>
        public String Encoding
        {
            get
            {
                return this.encoding;
            }
            set
            {
                this.encoding = value;
            }
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Default constructor
        /// </summary>
        public DataObjectFormat()
        {
            this.objectIdentifier = new ObjectIdentifier("ObjectIdentifier");
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Check to see if something has changed in this instance and needs to be serialized
        /// </summary>
        /// <returns>Flag indicating if a member needs serialization</returns>
        public Boolean HasChanged()
        {
            Boolean retVal = false;

            if (!String.IsNullOrEmpty(this.objectReferenceAttribute))
            {
                retVal = true;
            }

            if (!String.IsNullOrEmpty(this.description))
            {
                retVal = true;
            }

            if (this.objectIdentifier != null && this.objectIdentifier.HasChanged())
            {
                retVal = true;
            }

            if (!String.IsNullOrEmpty(this.mimeType))
            {
                retVal = true;
            }

            if (!String.IsNullOrEmpty(this.encoding))
            {
                retVal = true;
            }

            return retVal;
        }

        /// <summary>
        /// Load state from an XML element
        /// </summary>
        /// <param name="xmlElement">XML element containing new state</param>
        public void LoadXml(System.Xml.XmlElement xmlElement)
        {
            XmlNamespaceManager xmlNamespaceManager;
            XmlNodeList xmlNodeList;

            if (xmlElement == null)
            {
                throw new ArgumentNullException("xmlElement");
            }

            if (xmlElement.HasAttribute("ObjectReference"))
            {
                this.objectReferenceAttribute = xmlElement.GetAttribute("ObjectReference");
            }
            else
            {
                this.objectReferenceAttribute = "";
                throw new XadesCryptographicException("ObjectReference attribute missing");
            }

            xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace(XadesSignedXml.XadesNamespacePrefix, XadesSignedXml.XadesNamespaceUri);

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":Description", xmlNamespaceManager);
            if (xmlNodeList.Count != 0)
            {
                this.description = xmlNodeList.Item(0).InnerText;
            }

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":ObjectIdentifier", xmlNamespaceManager);
            if (xmlNodeList.Count != 0)
            {
                this.objectIdentifier = new ObjectIdentifier("ObjectIdentifier");
                this.objectIdentifier.LoadXml((XmlElement)xmlNodeList.Item(0));
            }

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":MimeType", xmlNamespaceManager);
            if (xmlNodeList.Count != 0)
            {
                this.mimeType = xmlNodeList.Item(0).InnerText;
            }

            xmlNodeList = xmlElement.SelectNodes(XadesSignedXml.XadesNamespacePrefix + ":Encoding", xmlNamespaceManager);
            if (xmlNodeList.Count != 0)
            {
                this.encoding = xmlNodeList.Item(0).InnerText;
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
            retVal = creationXmlDocument.CreateElement("DataObjectFormat", XadesSignedXml.XadesNamespaceUri);

            if ((this.objectReferenceAttribute != null) && ((this.objectReferenceAttribute != "")))
            {
                retVal.SetAttribute("ObjectReference", this.objectReferenceAttribute);
            }
            else
            {
                throw new XadesCryptographicException("Attribute ObjectReference missing");
            }

            if (!String.IsNullOrEmpty(this.description))
            {
                bufferXmlElement = creationXmlDocument.CreateElement("Description", XadesSignedXml.XadesNamespaceUri);
                bufferXmlElement.InnerText = this.description;
                retVal.AppendChild(bufferXmlElement);
            }

            if (this.objectIdentifier != null && this.objectIdentifier.HasChanged())
            {
                retVal.AppendChild(creationXmlDocument.ImportNode(this.objectIdentifier.GetXml(), true));
            }

            if (!String.IsNullOrEmpty(this.mimeType))
            {
                bufferXmlElement = creationXmlDocument.CreateElement("MimeType", XadesSignedXml.XadesNamespaceUri);
                bufferXmlElement.InnerText = this.mimeType;
                retVal.AppendChild(bufferXmlElement);
            }

            if (!String.IsNullOrEmpty(this.encoding))
            {
                bufferXmlElement = creationXmlDocument.CreateElement("Encoding", XadesSignedXml.XadesNamespaceUri);
                bufferXmlElement.InnerText = this.encoding;
                retVal.AppendChild(bufferXmlElement);
            }

            return retVal;
        }
        #endregion
    }
}
