using OSK.Security.Cryptography.Rsa.Internal.Services;
using OSK.Security.Cryptography.Rsa.Models;

namespace OSK.Security.Cryptography.Rsa.UnitTests.Internal.Services
{
    public class RsaKeyTests : AsymmetricKeyTests<RsaKeyInformation>
    {
        public RsaKeyTests()
            : base(new RsaKeyService(RsaKeyInformation.New(128)))
        {
        }
    }
}
