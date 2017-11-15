using System.Security.Cryptography;
using System.Text;

namespace Utils.Encrypt
{
	public class Md5Encrypt
	{
		public static string Encrypt(string content)
		{
			//将输入转换为ASCII 字符编码
			var enc = new ASCIIEncoding();
			//将字符串转换为字节数组
			var buffer = enc.GetBytes(content);
			//创建MD5实例
			MD5 md5 = new MD5CryptoServiceProvider();
			//进行MD5加密
			var hash = md5.ComputeHash(buffer);
			var sb = new StringBuilder();
			//拼装加密后的字符
			foreach (var t in hash)
			{
				sb.AppendFormat("{0:x2}", t);
			}
			//输出加密后的字符串
			return sb.ToString();
		}
	}
}
