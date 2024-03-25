using OSK.Security.Cryptography.Abstractions;
using System.Text;
using Xunit;

namespace OSK.Security.Cryptography.Rsa.UnitTests
{
    public abstract class CryptographicKeyTests<T>
        where T: AsymmetricKeyInformation
    {
        #region Variables

        private readonly ICryptographicKeyService<T> _keyService;

        #endregion

        #region Constructors

        public CryptographicKeyTests(ICryptographicKeyService<T> keyService)
        {
            _keyService = keyService;
        }

        #endregion

        #region EncryptAsync

        [Fact]
        public async Task EncryptAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await _keyService.EncryptAsync(null));
        }

        [Fact]
        public async Task EncryptAsync_Valid_EncryptsData()
        {
            // Arrange
            var phrase = "A day in the life of a unit test.";
            var data = Encoding.UTF8.GetBytes(phrase);

            // Act
            var encryptedData = await _keyService.EncryptAsync(data);

            // Assert
            Assert.NotEqual(phrase, Encoding.UTF8.GetString(encryptedData));
        }

        #endregion

        #region DecryptAsync

        [Fact]
        public async Task DecryptAsync_NullData_ThrowsArgumentNullException()
        {
            // Arrange/Act/Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await _keyService.DecryptAsync(null));
        }

        [Fact]
        public async Task DecryptAsync_Valid_DecryptsData()
        {
            // Arrange
            var phrase = "A day in the life of a unit test.";
            var data = Encoding.UTF8.GetBytes(phrase);
            var encryptedData = await _keyService.EncryptAsync(data);

            // Act
            var decryptedData = await _keyService.DecryptAsync(encryptedData);

            // Assert
            Assert.Equal(phrase, Encoding.UTF8.GetString(decryptedData));
        }

        #endregion
    }
}
