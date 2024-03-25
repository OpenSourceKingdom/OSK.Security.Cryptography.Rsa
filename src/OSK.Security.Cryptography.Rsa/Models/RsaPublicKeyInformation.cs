using OSK.Security.Cryptography.Abstractions;
using System.Security.Cryptography;

namespace OSK.Security.Cryptography.Rsa.Models
{
    public class RsaPublicKeyInformation : PublicKeyInformation
    {
        public byte[] PublicKey { get; set; }

        public RSAEncryptionPadding EncryptionPadding { get; set; }

        public RSASignaturePadding SignaturePadding { get; set; }
    }
}
