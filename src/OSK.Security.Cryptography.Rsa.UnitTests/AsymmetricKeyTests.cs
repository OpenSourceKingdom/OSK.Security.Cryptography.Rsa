using OSK.Security.Cryptography.Abstractions;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace OSK.Security.Cryptography.Rsa.UnitTests
{
    public abstract class AsymmetricKeyTests<T> : CryptographicKeyTests<T>
        where T: AsymmetricKeyInformation
    {
        #region Variables

        protected IAsymmetricKeyService<T> KeyService;

        #endregion

        #region Constructors

        public AsymmetricKeyTests(IAsymmetricKeyService<T> keyService)
            : base(keyService)
        {
            KeyService = keyService;
        }

        #endregion

        #region SignAsync

        [Fact]
        public async Task SignAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await KeyService.SignAsync(null, HashAlgorithmName.SHA256));
        }

        [Fact]
        public async Task SignAsync_Valid_ReturnsSignedData()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("A day in the life of a unit test.");

            // Act
            var signedData = await KeyService.SignAsync(data, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotEqual(BitConverter.ToInt64(data), BitConverter.ToInt64(signedData));
        }

        #endregion

        #region ValidateSignatureAsync

        [Fact]
        public async Task ValidateSignatureAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await KeyService.ValidateSignatureAsync(null, new byte[0], HashAlgorithmName.SHA256)); ;
        }

        [Fact]
        public async Task ValidateSignatureAsync_NullSignature_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await KeyService.ValidateSignatureAsync(new byte[0], null, HashAlgorithmName.SHA256));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task ValidateSignatureAsync_InvalidSignature_ReturnsFalse(bool wrongHash)
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("A day in the life of a unit test.");
            var signedData = await KeyService.SignAsync(data, HashAlgorithmName.SHA256);

            // Act
            var validationResult = await KeyService.ValidateSignatureAsync(data,
                wrongHash ? signedData : new byte[0],
                wrongHash ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256);

            // Assert
            Assert.False(validationResult);
        }

        [Fact]
        public async Task ValidateSignatureAsync_ValidSignature_ReturnsTrue()
        {
            // Arrange
            var data = Encoding.UTF8.GetBytes("A day in the life of a unit test.");
            var signedData = await KeyService.SignAsync(data, HashAlgorithmName.SHA256);

            // Act
            var validationResult = await KeyService.ValidateSignatureAsync(data, signedData, HashAlgorithmName.SHA256);

            // Assert
            Assert.True(validationResult);
        }

        #endregion
    }
}
