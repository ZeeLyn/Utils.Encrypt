using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Utils.Encrypt
{
    public static class RSA
    {
        #region Encrypt
        public static string EncryptWithPublicKey(string sourceString, string publicKey, RSAEncryptionPadding encryptionPadding = null)
        {
            return EncryptWithPublicXmlKey(sourceString, RSATransUtil.RSAPublicKeyJava2DotNet(publicKey), encryptionPadding);
        }

        public static string EncryptWithPrivateKey(string sourceString, string privateKey, RSAEncryptionPadding encryptionPadding = null)
        {
            return EncryptWithPublicXmlKey(sourceString, RSATransUtil.RSAPrivateKeyJava2DotNet(privateKey), encryptionPadding);
        }

        public static string EncryptWithPublicXmlKey(string sourceString, string publicXmlKey, RSAEncryptionPadding encryptionPadding = null)
        {
            using (var rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.ImportParameters(GenerateParametersFromPublicXmlKey(publicXmlKey));
                return Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(sourceString), encryptionPadding == null ? RSAEncryptionPadding.Pkcs1 : encryptionPadding));
            }
        }

        public static string EncryptWithPrivateXmlKey(string sourceString, string privateXmlKey, RSAEncryptionPadding encryptionPadding = null)
        {
            using (var rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.ImportParameters(GenerateParametersFromPrivateXmlKey(privateXmlKey));
                return Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(sourceString), encryptionPadding == null ? RSAEncryptionPadding.Pkcs1 : encryptionPadding));
            }
        }
        #endregion

        #region Decrypt
        public static string DecryptWithPrivateKey(string encryptString, string privateKey, RSAEncryptionPadding encryptionPadding = null)
        {
            return DecryptWithPrivateXmlKey(encryptString, RSATransUtil.RSAPrivateKeyJava2DotNet(privateKey), encryptionPadding);
        }

        public static string DecryptWithPrivateXmlKey(string encryptString, string privateXmlKey, RSAEncryptionPadding encryptionPadding = null)
        {
            using (var rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.ImportParameters(GenerateParametersFromPrivateXmlKey(privateXmlKey));
                return Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(encryptString), encryptionPadding == null ? RSAEncryptionPadding.Pkcs1 : encryptionPadding));
            }
        }

        #endregion

        public static string Sign(string sourceString, string privateKey, RSASignaturePadding signaturePadding = null)
        {
            return SignWithXmlKey(sourceString, RSATransUtil.RSAPrivateKeyJava2DotNet(privateKey), signaturePadding);
        }

        public static string SignWithXmlKey(string sourceString, string privateXmlKey, RSASignaturePadding signaturePadding = null)
        {
            using (var rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.ImportParameters(GenerateParametersFromPrivateXmlKey(privateXmlKey));
                var dataBytes = Encoding.UTF8.GetBytes(sourceString);
                var signatureBytes = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, signaturePadding == null ? RSASignaturePadding.Pkcs1 : signaturePadding);
                return Convert.ToBase64String(signatureBytes);
            }
        }


        public static bool Verify(string sourceString, string signString, string publicKey, RSASignaturePadding signaturePadding = null)
        {
            return VerifyWithXmlKey(sourceString, signString, RSATransUtil.RSAPublicKeyJava2DotNet(publicKey), signaturePadding);
        }

        public static bool VerifyWithXmlKey(string sourceString, string signString, string publicXmlKey, RSASignaturePadding signaturePadding = null)
        {
            using (var rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.ImportParameters(GenerateParametersFromPublicXmlKey(publicXmlKey));
                var dataBytes = Encoding.UTF8.GetBytes(sourceString);
                var signBytes = Convert.FromBase64String(signString);
                var verify = rsa.VerifyData(dataBytes, signBytes, HashAlgorithmName.SHA256, signaturePadding == null ? RSASignaturePadding.Pkcs1 : signaturePadding);
                return verify;
            }
        }

        #region Private methods

        private static RSAParameters GenerateParametersFromPrivateKey(string privateKey)
        {
            return GenerateParametersFromPrivateXmlKey(RSATransUtil.RSAPrivateKeyJava2DotNet(privateKey));
        }

        private static RSAParameters GenerateParametersFromPrivateXmlKey(string privateXmlKey)
        {
            var doc = XElement.Parse(privateXmlKey);
            return new RSAParameters
            {
                Modulus = Convert.FromBase64String(doc.Element("Modulus")?.Value ?? ""),
                Exponent = Convert.FromBase64String(doc.Element("Exponent")?.Value ?? ""),
                D = Convert.FromBase64String(doc.Element("D")?.Value ?? ""),
                P = Convert.FromBase64String(doc.Element("P")?.Value ?? ""),
                Q = Convert.FromBase64String(doc.Element("Q")?.Value ?? ""),
                DP = Convert.FromBase64String(doc.Element("DP")?.Value ?? ""),
                DQ = Convert.FromBase64String(doc.Element("DQ")?.Value ?? ""),
                InverseQ = Convert.FromBase64String(doc.Element("InverseQ")?.Value ?? ""),
            };
        }

        private static RSAParameters GenerateParametersFromPublicXmlKey(string publicXmlKey)
        {
            var doc = XElement.Parse(publicXmlKey);
            return new RSAParameters
            {
                Modulus = Convert.FromBase64String(doc.Element("Modulus")?.Value ?? ""),
                Exponent = Convert.FromBase64String(doc.Element("Exponent")?.Value ?? "")
            };
        }
        #endregion
    }

}
