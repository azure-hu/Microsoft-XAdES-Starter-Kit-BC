﻿// XadesSignedXml.cs
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
}
