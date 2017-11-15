using System;
using System.Security.Cryptography;
using System.Text;

namespace Utils.Encrypt
{
	public class HMACSHA256Ecryptor
	{
		public static string Encrypt(string sourceText, string secret = null)
		{
			secret = secret ?? "";
			var encoding = new ASCIIEncoding();
			var keyByte = encoding.GetBytes(secret);
			var messageBytes = encoding.GetBytes(sourceText);
			using (var hmacsha256 = new HMACSHA256(keyByte))
			{
				var hashmessage = hmacsha256.ComputeHash(messageBytes);
				return Convert.ToBase64String(hashmessage);
			}
		}
	}
	public class HMACSHA384Ecryptor
	{
		public static string Encrypt(string sourceText, string secret = null)
		{
			secret = secret ?? "";
			var encoding = new ASCIIEncoding();
			var keyByte = encoding.GetBytes(secret);
			var messageBytes = encoding.GetBytes(sourceText);
			using (var hmacsha256 = new HMACSHA384(keyByte))
			{
				var hashmessage = hmacsha256.ComputeHash(messageBytes);
				return Convert.ToBase64String(hashmessage);
			}

		}
	}
	public class HMACSHA512Ecryptor
	{
		public static string Encrypt(string sourceText, string secret = null)
		{
			secret = secret ?? "";
			var encoding = new ASCIIEncoding();
			var keyByte = encoding.GetBytes(secret);
			var messageBytes = encoding.GetBytes(sourceText);
			using (var hmacsha256 = new HMACSHA512(keyByte))
			{
				var hashmessage = hmacsha256.ComputeHash(messageBytes);
				return Convert.ToBase64String(hashmessage);
			}

		}
	}
}
