using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using OSK.Security.Cryptography.Rsa.Models;
using OSK.Security.Cryptography.Abstractions;
using System.Collections.Generic;

namespace OSK.Security.Cryptography.Rsa.Internal.Services
{
    internal class RsaKeyService : AsymmetricKeyService<RsaKeyInformation>
    {
        #region Constructors

        public RsaKeyService()
        {
        }

        internal RsaKeyService(RsaKeyInformation keyInformation)
        {
            KeyInformation = keyInformation;
        }

        #endregion

        #region AsymmetricCryptographicKey Overrides

        public override IEnumerable<CryptographicSigningAlgorithm> SupportedSigningAlgorithms => new CryptographicSigningAlgorithm[]
        {
            ClassicSigningAlgorithms.MD5,
            ClassicSigningAlgorithms.SHA1,
            ClassicSigningAlgorithms.SHA256,
            ClassicSigningAlgorithms.SHA384,
            ClassicSigningAlgorithms.SHA512
        };

        public override ValueTask<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var cipher = GetCipher(KeyInformation.EncryptionPadding);
            cipher.Init(true, KeyInformation.PublicKey);
            return new ValueTask<byte[]>(cipher.ProcessBlock(data, 0, data.Length));
        }

        public override ValueTask<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var cipher = GetCipher(KeyInformation.EncryptionPadding);
            cipher.Init(false, KeyInformation.PrivateKey);
            return new ValueTask<byte[]>(cipher.ProcessBlock(data, 0, data.Length));
        }

        public override ValueTask<byte[]> SignAsync(byte[] data, CryptographicSigningAlgorithm signingAlgorithm, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            ValidateSigningAlgorithmSupport(signingAlgorithm);

            var signer = GetSigner(KeyInformation.SignaturePadding, new HashAlgorithmName(signingAlgorithm.AlgorithmName));
            signer.Init(true, KeyInformation.PrivateKey);
            signer.BlockUpdate(data, 0, data.Length);
            return new ValueTask<byte[]>(signer.GenerateSignature());
        }

        public override ValueTask<bool> ValidateSignatureAsync(byte[] data, byte[] signedData, CryptographicSigningAlgorithm signingAlgorithm, CancellationToken cancellationToken = default)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (signedData == null)
            {
                throw new ArgumentNullException(nameof(signedData));
            }

            ValidateSigningAlgorithmSupport(signingAlgorithm);

            var signer = GetSigner(KeyInformation.SignaturePadding, new HashAlgorithmName(signingAlgorithm.AlgorithmName));
            signer.Init(false, KeyInformation.PublicKey);
            signer.BlockUpdate(data, 0, data.Length);
            return new ValueTask<bool>(signer.VerifySignature(signedData));
        }

        #endregion

        #region Helpers

        private ISigner GetSigner(RSASignaturePadding signaturePadding, HashAlgorithmName hashAlgorithmName) => signaturePadding.Mode switch
        {
            RSASignaturePaddingMode.Pss => new PssSigner(new RsaBlindedEngine(), DigestUtilities.GetDigest(hashAlgorithmName.Name)),
            RSASignaturePaddingMode.Pkcs1 => new RsaDigestSigner(DigestUtilities.GetDigest(hashAlgorithmName.Name)),
            _ => throw new NotSupportedException($"Signature Padding mode {signaturePadding} is not currently supported for RSA security key.")
        };

        private IAsymmetricBlockCipher GetCipher(RSAEncryptionPadding padding) => padding.Mode switch
        {
            RSAEncryptionPaddingMode.Pkcs1 => new Pkcs1Encoding(new RsaEngine()),
            RSAEncryptionPaddingMode.Oaep => new OaepEncoding(new RsaEngine(), DigestUtilities.GetDigest(padding.OaepHashAlgorithm.Name)),
            _ => throw new NotSupportedException($"Encryption Padding mode {padding} is not currently supported for RSA security key.")
        };

        #endregion
    }
}
