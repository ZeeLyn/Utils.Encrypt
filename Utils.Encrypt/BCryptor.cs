using bCrypt = BCrypt.Net;
namespace Utils.Encrypt
{
	public class BCryptor
	{
		public static string GenerateSalt()
		{
			return bCrypt.BCrypt.GenerateSalt();
		}

		public static string Encrypt(string sourceText, string salt = null)
		{
			return bCrypt.BCrypt.HashPassword(sourceText, string.IsNullOrWhiteSpace(salt) ? GenerateSalt() : salt);
		}

		public static bool Verify(string sourceText, string hash)
		{
			return bCrypt.BCrypt.Verify(sourceText, hash);
		}
	}
}
