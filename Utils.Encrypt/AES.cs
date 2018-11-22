using System;
using System.Security.Cryptography;
using System.Text;

namespace Utils.Encrypt
{
	public class AES
	{
		public static string GenerateKey()
		{
			return Guid.NewGuid().ToString("N");
		}

		public static string Encrypt(string sourceText, string key)
		{
			var toEncryptArray = Encoding.UTF8.GetBytes(sourceText);
			using (var rm = new RijndaelManaged
			{
				Key = Encoding.UTF8.GetBytes(key),
				Mode = CipherMode.ECB,
				Padding = PaddingMode.PKCS7
			})
			{
				var cTransform = rm.CreateEncryptor();
				var resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
				rm.Clear();
				return Convert.ToBase64String(resultArray, 0, resultArray.Length);
			}
		}

		public static string Decrypt(string encryptText, string key)
		{
			var toEncryptArray = Convert.FromBase64String(encryptText);
			using (var rm = new RijndaelManaged
			{
				Key = Encoding.UTF8.GetBytes(key),
				Mode = CipherMode.ECB,
				Padding = PaddingMode.PKCS7
			})
			{
				var cTransform = rm.CreateDecryptor();
				var resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
				return Encoding.UTF8.GetString(resultArray);
			}
		}
	}
}
