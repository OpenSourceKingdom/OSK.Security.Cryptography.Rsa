using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using OSK.Security.Cryptography.Models;
using System;
using System.Security.Cryptography;

namespace OSK.Security.Cryptography.Rsa.Models
{
    public class RsaKeyInformation : AsymmetricKeyInformation<RsaPublicKeyInformation>
    {
        #region Static

        private const long DefaultPublicExponent = 65537;
        private const int NumberOfTestsForPrime = 500;
        private static readonly KeySizes ValidKeySizes = new KeySizes(128, 512, 64);

        public static RsaKeyInformation New(int keySize,
            RSAEncryptionPadding encryptionPadding = null, RSASignaturePadding signaturePadding = null)
        {
            CryptographicKeyHelpers.ValidateKeySize(keySize, ValidKeySizes);

            encryptionPadding ??= RSAEncryptionPadding.OaepSHA256;
            signaturePadding ??= RSASignaturePadding.Pkcs1;

            var rsaKeyGenerator = new RsaKeyPairGenerator();
            rsaKeyGenerator.Init(new Org.BouncyCastle.Crypto.Parameters.RsaKeyGenerationParameters(BigInteger.ValueOf(DefaultPublicExponent),
                new SecureRandom(),
                keySize * 8, // BouncyCastle uses bit length
                NumberOfTestsForPrime));

            var key = rsaKeyGenerator.GenerateKeyPair();
            return new RsaKeyInformation(key.Public, key.Private, encryptionPadding, signaturePadding);
        }

        #endregion

        #region Variables

        public AsymmetricKeyParameter PublicKey { get; }

        public AsymmetricKeyParameter PrivateKey { get; private set; }

        public RSAEncryptionPadding EncryptionPadding { get; }

        public RSASignaturePadding SignaturePadding { get; }

        #endregion

        #region Constructors

        public RsaKeyInformation(AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey,
            RSAEncryptionPadding encryptionPadding, RSASignaturePadding signaturePadding)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            EncryptionPadding = encryptionPadding ?? throw new ArgumentNullException(nameof(encryptionPadding));
            SignaturePadding = signaturePadding ?? throw new ArgumentNullException(nameof(signaturePadding));
        }

        public RsaKeyInformation(byte[] privateKey, RsaPublicKeyInformation publicKeyInformation)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (publicKeyInformation.PublicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKeyInformation.PublicKey));
            }

            var rsaPublicKey = PublicKeyFactory.CreateKey(publicKeyInformation.PublicKey);
            var rsaPrivateKey = PrivateKeyFactory.CreateKey(privateKey);

            PublicKey = rsaPublicKey;
            PrivateKey = rsaPrivateKey;
            EncryptionPadding = publicKeyInformation.EncryptionPadding;
            SignaturePadding = publicKeyInformation.SignaturePadding;
        }

        #endregion

        #region AsymmetricKeyInformation Overrides

        public override RsaPublicKeyInformation GetPublicKeyInformation()
        {
            return new RsaPublicKeyInformation()
            {
                PublicKey = PublicKey.AsBytes(),
                EncryptionPadding = EncryptionPadding,
                SignaturePadding = SignaturePadding
            };
        }

        public override void Dispose()
        {
            PrivateKey = null;
        }

        #endregion
    }
}
