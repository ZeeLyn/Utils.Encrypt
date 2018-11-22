# Utils.Encrypt

```csharp
class Program
	{
		static void Main(string[] args)
		{

			Console.WriteLine("SHA1:" + Hash.SHA1("abc"));
			Console.WriteLine("SHA256:" + Hash.SHA256("abc"));
			Console.WriteLine("SHA384:" + Hash.SHA384("abc"));
			Console.WriteLine("SHA512:" + Hash.SHA512("abc"));
			Console.WriteLine("MD5:" + Hash.MD5("abc"));
			Console.WriteLine("HamcSHA1:" + Hash.HMACSHA1("abc", "123"));
			Console.WriteLine("HamcSHA256:" + Hash.HMACSHA256("abc", "123"));
			Console.WriteLine("HamcSHA384:" + Hash.HMACSHA384("abc", "123"));
			Console.WriteLine("HamcSHA512:" + Hash.HMACSHA512("abc", "123"));
			Console.WriteLine("HamcMD5:" + Hash.HMACMD5("abc", "123"));

			var aesKey = AES.GenerateKey();
			Console.WriteLine($"AES Key:{aesKey}");
			var aesEncrypt = AES.Encrypt("abc", aesKey);
			Console.WriteLine($"AES Encrypt:{aesEncrypt}");
			Console.WriteLine($"AES Decrypt:{AES.Decrypt(aesEncrypt, aesKey)}");

			var bCrypt = BCryptor.Encrypt("abc", BCryptor.GenerateSalt());
			Console.WriteLine($"BCrypt:{bCrypt}");
			Console.WriteLine($"BCrypt Verify:{BCryptor.Verify("abc", bCrypt)}");
			Console.ReadKey();
		}
	}
```
