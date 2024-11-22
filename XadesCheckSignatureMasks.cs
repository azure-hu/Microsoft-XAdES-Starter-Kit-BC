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

using System;

namespace Microsoft.Xades.BC
{
    /// <summary>
    /// Bitmasks to indicate which checks need to be executed on the XAdES signature
    /// </summary>
    [Flags]
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
}