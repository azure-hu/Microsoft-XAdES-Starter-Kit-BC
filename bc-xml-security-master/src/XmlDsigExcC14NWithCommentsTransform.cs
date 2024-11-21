﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace Org.BouncyCastle.Crypto.Xml
{
    // <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
    //     <ec:InclusiveNamespaces PrefixList="dsig soap #default" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    // </ds:Transform>

    public class XmlDsigExcC14NWithCommentsTransform : XmlDsigExcC14NTransform
    {
        public XmlDsigExcC14NWithCommentsTransform() : base(true)
        {
            Algorithm = SignedXml.XmlDsigExcC14NWithCommentsTransformUrl;
        }

        public XmlDsigExcC14NWithCommentsTransform(string inclusiveNamespacesPrefixList) : base(true, inclusiveNamespacesPrefixList)
        {
            Algorithm = SignedXml.XmlDsigExcC14NWithCommentsTransformUrl;
        }
    }
}
