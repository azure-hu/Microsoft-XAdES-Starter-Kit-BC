﻿// IssuerSerial.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
//
// Originally published under the CECILL-B Free Software license agreement,
// modified by Dpto. de Nuevas Tecnologнas de la Direcciуn General de Urbanismo del Ayto. de Cartagena
// and published under the GNU Lesser General Public License version 3.
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
using System;
using System.Xml;

namespace Microsoft.Xades.BC
{
    /// <summary>
    /// The element IssuerSerialV2 contains the identifier of one of the
    /// certificates referenced in the sequence
    /// </summary>
    public class IssuerSerialV2
    {
        /// <summary>
        /// Gets or sets the bytes.
        /// </summary>
        public Byte[] Bytes { get; set; }
        /// <summary>
        /// Check to see if something has changed in this instance and needs to be serialized
        /// </summary>
        /// <returns>Flag indicating if a member needs serialization</returns>
        public Boolean HasChanged()
        {
            return this.Bytes != null && this.Bytes.Length != 0;
        }

        /// <summary>
        /// Load state from an XML element
        /// </summary>
        /// <param name="xmlElement">XML element containing new state</param>
        public void LoadXml(XmlElement xmlElement)
        {
            if (xmlElement is null)
            {
                throw new ArgumentNullException(nameof(xmlElement));
            }
            this.Bytes = Convert.FromBase64String(xmlElement.InnerText);
        }
        /// <summary>
        /// Returns the XML representation of the this object
        /// </summary>
        /// <returns>XML element containing the state of this object</returns>
        public XmlElement GetXml()
        {
            XmlDocument creationXmlDocument = new XmlDocument();
            XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XadesNamespacePrefix, "IssuerSerialV2", XadesSignedXml.XadesNamespaceUri);
            if (this.Bytes != null && this.Bytes.Length > 0)
            {
                result.InnerText = Convert.ToBase64String(this.Bytes);
            }
            return result;
        }
    }
}