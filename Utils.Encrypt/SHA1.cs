using System;
using System.Security.Cryptography;
using System.Text;

namespace Utils.Encrypt
{
	public class SHA1
	{
		public static string Encrypt(string content)
		{
			try
			{
				var sha1 = new SHA1CryptoServiceProvider();
				var bytesIn = Encoding.UTF8.GetBytes(content);
				var bytesOut = sha1.ComputeHash(bytesIn);
				sha1.Dispose();
				var result = BitConverter.ToString(bytesOut);
				result = result.Replace("-", "");
				return result;
			}
			catch (Exception ex)
			{
				throw new Exception("SHA1加密出错：" + ex.Message);
			}
		}
	}
}
