using System;
using System.Security.Cryptography;
using System.Text;

namespace Utils.Encrypt
{
    public static class Hash
    {
        private static readonly char[] _digitals =
            { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        private static readonly MD5 Md5 = System.Security.Cryptography.MD5.Create();
        private static readonly SHA1 Sha1 = System.Security.Cryptography.SHA1.Create();
        private static readonly SHA256 Sha256 = System.Security.Cryptography.SHA256.Create();
        private static readonly SHA384 Sha384 = System.Security.Cryptography.SHA384.Create();
        private static readonly SHA512 Sha512 = System.Security.Cryptography.SHA512.Create();

        public static string SHA1(string sourceText)
        {
            var bytesIn = Encoding.UTF8.GetBytes(sourceText);
            Sha1.Initialize();
            var bytesOut = Sha1.ComputeHash(bytesIn);
            return BytesToString(bytesOut);
        }

        public static string SHA256(string sourceText)
        {
            var tmpByte = Encoding.UTF8.GetBytes(sourceText);
            Sha256.Initialize();
            var bytes = Sha256.ComputeHash(tmpByte);
            return BytesToString(bytes);
        }

        public static string SHA384(string sourceText)
        {
            var tmpByte = Encoding.UTF8.GetBytes(sourceText);
            Sha384.Initialize();
            var bytes = Sha384.ComputeHash(tmpByte);
            return BytesToString(bytes);
        }

        public static string SHA512(string sourceText)
        {
            var tmpByte = Encoding.UTF8.GetBytes(sourceText);
            Sha384.Initialize();
            var bytes = Sha512.ComputeHash(tmpByte);
            return BytesToString(bytes);
        }

        public static string MD5(string sourceText)
        {
            var buffer = Encoding.UTF8.GetBytes(sourceText);
            Md5.Initialize();
            var hash = Md5.ComputeHash(buffer);
            return BytesToString(hash);
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

        private static string BytesToString(byte[] bytes)
        {
            const int byteLen = 2;
            var chars = new char[byteLen * bytes.Length];
            var index = 0;
            foreach (var item in bytes)
            {
                chars[index] = _digitals[item >> 4 /* byte high */];
                ++index;
                chars[index] = _digitals[item & 15 /* byte low  */];
                ++index;
            }

            return new string(chars);
        }
    }
}