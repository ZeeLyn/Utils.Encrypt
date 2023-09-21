using System;
using System.Security.Cryptography;
using System.Text;

namespace Utils.Encrypt
{
    public static class AES
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sourceText"></param>
        /// <param name="key">16位密钥=128位，24位密钥=192位，32位密钥=256位</param>
        /// <param name="iv"></param>
        /// <param name="mode"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static string Encrypt(string sourceText, string key, string iv = null, CipherMode mode = CipherMode.ECB,
            PaddingMode padding = PaddingMode.PKCS7)
        {
            if (string.IsNullOrWhiteSpace(sourceText))
                throw new ArgumentNullException("sourceText");
            if (string.IsNullOrWhiteSpace(key)) throw new ArgumentNullException("key");
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Parameter key can only be a string composed of 16,24,32 characters.");
            if (mode != CipherMode.ECB)
            {
                if (string.IsNullOrWhiteSpace(iv))
                    throw new ArgumentNullException("iv");
                if (iv.Length != 16)
                    throw new ArgumentException("Parameter IV is a 16 -character string.");
            }

            var toEncryptArray = Encoding.UTF8.GetBytes(sourceText);
            using (var rm = new RijndaelManaged
                   {
                       Key = Encoding.UTF8.GetBytes(key),
                       Mode = mode,
                       Padding = padding,
                   })
            {
                if (mode != CipherMode.ECB)
                    rm.IV = Encoding.UTF8.GetBytes(iv);
                var cTransform = rm.CreateEncryptor();
                var resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                rm.Clear();
                return Convert.ToBase64String(resultArray, 0, resultArray.Length);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="encryptText"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="mode"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static string Decrypt(string encryptText, string key, string iv = null, CipherMode mode = CipherMode.ECB,
            PaddingMode padding = PaddingMode.PKCS7)
        {
            if (string.IsNullOrWhiteSpace(encryptText))
                throw new ArgumentNullException("encryptText");
            if (string.IsNullOrWhiteSpace(key)) throw new ArgumentNullException("key");
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Parameter key can only be a string composed of 16,24,32 characters.");
            if (mode != CipherMode.ECB)
            {
                if (string.IsNullOrWhiteSpace(iv))
                    throw new ArgumentNullException("iv");
                if (iv.Length != 16)
                    throw new ArgumentException("Parameter IV is a 16 -character string.");
            }

            var toEncryptArray = Convert.FromBase64String(encryptText);
            using (var rm = new RijndaelManaged
                   {
                       Key = Encoding.UTF8.GetBytes(key),
                       Mode = mode,
                       Padding = padding,
                   })
            {
                if (mode != CipherMode.ECB)
                    rm.IV = Encoding.UTF8.GetBytes(iv);
                var cTransform = rm.CreateDecryptor();
                var resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
                return Encoding.UTF8.GetString(resultArray);
            }
        }
    }
}