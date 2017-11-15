using System;
using System.IO;
using System.Security.Cryptography;

namespace Utils.Encrypt
{
	public class AES
	{
		public static string Encrypt(string encryptedDataStr, string key, string iv)
		{
			using (var aes = Aes.Create())
			{
				aes.Key = Convert.FromBase64String(key);
				aes.IV = Convert.FromBase64String(iv);
				string result;
				using (var encryptor = aes.CreateDecryptor(aes.Key, aes.IV))
				{
					using (var msDecrypt = new MemoryStream(Convert.FromBase64String(encryptedDataStr)))
					{
						using (var csDecrypt = new CryptoStream(msDecrypt, encryptor, CryptoStreamMode.Read))
						{
							using (var srDecrypt = new StreamReader(csDecrypt))
							{
								result = srDecrypt.ReadToEnd();
							}
						}
					}
				}
				return result;
			}
		}
	}
}
