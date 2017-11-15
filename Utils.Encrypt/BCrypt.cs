namespace Utils.Encrypt
{
	public class BCryptor
	{

		public static string GenerateSalt()
		{
			return BCrypt.Net.BCrypt.GenerateSalt();
		}

		/// <summary>
		/// 加密
		/// </summary>
		/// <param name="sourceText"></param>
		/// <param name="salt"></param>
		/// <returns></returns>
		public static string Encrypt(string sourceText, string salt = null)
		{
			if (string.IsNullOrWhiteSpace(salt))
				salt = BCrypt.Net.BCrypt.GenerateSalt();
			return BCrypt.Net.BCrypt.HashPassword(sourceText, salt);
		}

		/// <summary>
		/// 验证密码
		/// </summary>
		/// <param name="sourceText">预验证的密码</param>
		/// <param name="hash">加密后的字符串</param>
		/// <returns></returns>
		public static bool Verify(string sourceText, string hash)
		{
			return BCrypt.Net.BCrypt.Verify(sourceText, hash);
		}
	}
}
