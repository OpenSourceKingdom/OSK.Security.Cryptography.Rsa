using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;

namespace OSK.Security.Cryptography.Rsa
{
    public static class AsymmetricKeyParameterExtensions
    {
        public static byte[] AsBytes(this AsymmetricKeyParameter parameter) =>
             parameter switch
             {
                 RsaPrivateCrtKeyParameters rsaPrivateKey => PrivateKeyInfoFactory.CreatePrivateKeyInfo(rsaPrivateKey).ToAsn1Object().GetEncoded(),
                 RsaKeyParameters rsaPublicKey => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaPublicKey).ToAsn1Object().GetEncoded(),
                 null => throw new ArgumentNullException(nameof(parameter)),
                 _ => throw new NotSupportedException($"The asymmetric parameter type {parameter.GetType().FullName} is not currently supported for byte retrieval.")
             };
    }
}
