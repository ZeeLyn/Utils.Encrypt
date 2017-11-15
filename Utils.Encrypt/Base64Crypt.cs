using System;
using System.Text;

namespace Utils.Encrypt
{
	/// <summary>
	/// Base64编码
	/// </summary>
	public class Base64Encrypt
	{
		/// <summary>
		/// 加密
		/// </summary>
		/// <param name="content"></param>
		/// <returns></returns>
		public static string Encrypt(string content)
		{
			return Convert.ToBase64String(Encoding.UTF8.GetBytes(content));
		}

		/// <summary>
		/// 解密
		/// </summary>
		/// <param name="content"></param>
		/// <returns></returns>
		public static string Decrypt(string content)
		{
			return Encoding.UTF8.GetString(Convert.FromBase64String(content));
		}
	}
}
