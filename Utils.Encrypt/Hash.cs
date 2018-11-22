using System;
using System.Security.Cryptography;
using System.Text;

namespace Utils.Encrypt
{
	public static class Hash
	{
		public static string SHA1(string sourceText)
		{
			using (var sha1 = new SHA1CryptoServiceProvider())
			{
				var bytesIn = Encoding.UTF8.GetBytes(sourceText);
				var bytesOut = sha1.ComputeHash(bytesIn);
				sha1.Clear();
				return BitConverter.ToString(bytesOut).Replace("-", "").ToLower();
			}
		}

		public static string SHA256(string sourceText)
		{
			using (var sha256 = new SHA256Managed())
			{
				var tmpByte = Encoding.UTF8.GetBytes(sourceText);
				var bytes = sha256.ComputeHash(tmpByte);
				sha256.Clear();
				return BitConverter.ToString(bytes).Replace("-", "").ToLower();
			}
		}

		public static string SHA384(string sourceText)
		{
			using (var sha384 = new SHA384Managed())
			{
				var tmpByte = Encoding.UTF8.GetBytes(sourceText);
				var bytes = sha384.ComputeHash(tmpByte);
				sha384.Clear();
				return BitConverter.ToString(bytes).Replace("-", "").ToLower();
			}
		}

		public static string SHA512(string sourceText)
		{
			using (var sha512 = new SHA512Managed())
			{
				var tmpByte = Encoding.UTF8.GetBytes(sourceText);
				var bytes = sha512.ComputeHash(tmpByte);
				sha512.Clear();
				return BitConverter.ToString(bytes).Replace("-", "").ToLower();
			}
		}

		public static string MD5(string sourceText)
		{
			var buffer = Encoding.UTF8.GetBytes(sourceText);
			using (MD5 md5 = new MD5CryptoServiceProvider())
			{
				var hash = md5.ComputeHash(buffer);
				md5.Clear();
				return BitConverter.ToString(hash).Replace("-", "").ToLower();
			}
		}

		public static string HMACSHA1(string sourceText, string key)
		{
			var keyByte = Encoding.UTF8.GetBytes(key);
			var sourceBytes = Encoding.UTF8.GetBytes(sourceText);
			using (var hmacSha1 = new HMACSHA1(keyByte))
			{
				var bytes = hmacSha1.ComputeHash(sourceBytes);
				hmacSha1.Clear();
				return BitConverter.ToString(bytes).Replace("-", "").ToLower();
			}
		}


		public static string HMACSHA256(string sourceText, string key)
		{
			var keyByte = Encoding.UTF8.GetBytes(key);
			var sourceBytes = Encoding.UTF8.GetBytes(sourceText);
			using (var hmacSha256 = new HMACSHA256(keyByte))
			{
				var bytes = hmacSha256.ComputeHash(sourceBytes);
				hmacSha256.Clear();
				return BitConverter.ToString(bytes).Replace("-", "").ToLower();
			}
		}
		public static string HMACSHA384(string sourceText, string key)
		{
			var keyByte = Encoding.UTF8.GetBytes(key);
			var sourceBytes = Encoding.UTF8.GetBytes(sourceText);
			using (var hmacSha384 = new HMACSHA384(keyByte))
			{
				var bytes = hmacSha384.ComputeHash(sourceBytes);
				hmacSha384.Clear();
				return BitConverter.ToString(bytes).Replace("-", "").ToLower();
			}
		}

		public static string HMACSHA512(string sourceText, string key)
		{
			var keyByte = Encoding.UTF8.GetBytes(key);
			var sourceBytes = Encoding.UTF8.GetBytes(sourceText);
			using (var hmacSha512 = new HMACSHA512(keyByte))
			{
				var bytes = hmacSha512.ComputeHash(sourceBytes);
				hmacSha512.Clear();
				return BitConverter.ToString(bytes).Replace("-", "").ToLower();
			}
		}

		public static string HMACMD5(string sourceText, string key)
		{
			var keyByte = Encoding.UTF8.GetBytes(key);
			var sourceBytes = Encoding.UTF8.GetBytes(sourceText);
			using (var hmacMd5 = new HMACMD5(keyByte))
			{
				var bytes = hmacMd5.ComputeHash(sourceBytes);
				hmacMd5.Clear();
				return BitConverter.ToString(bytes).Replace("-", "").ToLower();
			}
		}
	}
}
