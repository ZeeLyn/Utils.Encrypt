using System;
using System.Text;

namespace Utils.Encrypt
{
    public static class Base64
    {
        public static string Encrypt(string content)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(content));
        }

        public static string Decrypt(string content)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(content));
        }
    }
}
