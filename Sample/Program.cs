using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Utils.Encrypt;
using RSA = Utils.Encrypt.RSA;


namespace Sample
{
    class Program
    {
        public static string Decrypt(string toDecrypt, string key)
        {
            byte[] keyArray = Encoding.UTF8.GetBytes(key);
            byte[] toEncryptArray = Convert.FromBase64String(toDecrypt);

            RijndaelManaged rDel = new RijndaelManaged();
            rDel.Key = keyArray;
            rDel.Mode = CipherMode.ECB;
            rDel.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = rDel.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Encoding.UTF8.GetString(resultArray);
        }


        //public static string Decrypt(string toDecrypt, string key, string iv)
        //{
        //    byte[] keyArray = UTF8Encoding.UTF8.GetBytes(key);
        //    byte[] ivArray = UTF8Encoding.UTF8.GetBytes(iv);
        //    byte[] toEncryptArray = Convert.FromBase64String(toDecrypt);
        //    RijndaelManaged rDel = new RijndaelManaged();
        //    rDel.Key = keyArray;
        //    rDel.IV = ivArray;
        //    rDel.Mode = CipherMode.CBC;
        //    rDel.Padding = PaddingMode.PKCS7;
        //    ICryptoTransform cTransform = rDel.CreateDecryptor();
        //    byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
        //    return UTF8Encoding.UTF8.GetString(resultArray);
        //}


        public static string Decrypt(string cipherText, string key, string iv)
        {
            string plainText = "";

            RijndaelManaged rijndael = new RijndaelManaged();
            ICryptoTransform transform =
                rijndael.CreateDecryptor(UTF8Encoding.UTF8.GetBytes(key), UTF8Encoding.UTF8.GetBytes(iv));
            byte[] bCipherText = Convert.FromBase64String(cipherText); //这里要用这个函数来正确转换Base64字符串成Byte数组
            MemoryStream ms = new MemoryStream(bCipherText);
            CryptoStream cs = new CryptoStream(ms, transform, CryptoStreamMode.Read);
            byte[] bPlainText = new byte[bCipherText.Length];
            cs.Read(bPlainText, 0, bPlainText.Length);
            plainText = Encoding.UTF8.GetString(bPlainText);
            plainText = plainText.Trim('\0');

            return plainText;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("SHA1:" + Hash.SHA1("abc"));
            Console.WriteLine("SHA256:" + Hash.SHA256("abc"));
            Console.WriteLine("SHA384:" + Hash.SHA384("abc"));
            Console.WriteLine("SHA512:" + Hash.SHA512("abc"));
            Console.WriteLine("MD5:" + Hash.MD5("abc"));
            Console.WriteLine("MD5:" + Hash.MD5("edg"));
            Console.WriteLine("HamcSHA1:" + Hash.HMACSHA1("abc", "123"));
            Console.WriteLine("HamcSHA256:" + Hash.HMACSHA256("abc", "123"));
            Console.WriteLine("HamcSHA384:" + Hash.HMACSHA384("abc", "123"));
            Console.WriteLine("HamcSHA512:" + Hash.HMACSHA512("abc", "123"));
            Console.WriteLine("HamcMD5:" + Hash.HMACMD5("abc", "123"));

            var aesKey = RandomString.Generate(32);
            var aesIv = RandomString.Generate(16);
            Console.WriteLine($"AES Key:{aesKey}");
            Console.WriteLine($"AES IV:{aesIv}");
            var aesEncrypt = AES.Encrypt("abc", aesKey, aesIv, CipherMode.CBC);
            Console.WriteLine($"AES Encrypt:{aesEncrypt}");
            Console.WriteLine($"AES Decrypt:{AES.Decrypt(aesEncrypt, aesKey, aesIv, CipherMode.CBC)}");


            var bCrypt = BCryptor.Encrypt("abc", BCryptor.GenerateSalt());
            Console.WriteLine($"BCrypt:{bCrypt}");
            Console.WriteLine($"BCrypt Verify:{BCryptor.Verify("abc", bCrypt)}");


            string publicXmlKey =
                "<RSAKeyValue><Modulus>w8oD7lBQrovytxepkGJ9vIBlEWZIeYTL+UrbDaLuw2uBGL8akcMnGKzj3D8fKaXejNzN3ls7AJfS7OsHb3+lJrCJUXVfshw/3nZumfYmNbsjQjU8o2g+zyU7ykIRZlcMRynmBFYsbvW4PZKLDaE7GuODiDamdYq5Fq3ZIhBTxLc2J5f50FHiQ1FBUW4oF+CM2QKr/dl1DdCAcWbnYKRTLvvxHwIc0LyfVEF8gQMKrrSoNAsDdqr2eUVuWYP0HH668H8Og59rFXEoXkzhIJiYLtVYJVmCfcyBG7UJwG/vFi2uDrvy0d64ItY88jniW2BSrWKZp7+kMNSpwc1gz73jrQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

            //2048 public key
            string publicKey = RSATransUtil.RSAPublicKeyDotNet2Java(publicXmlKey);
            Console.WriteLine("publicKey:{0}", publicKey);


            string privateXmlKey =
                "<RSAKeyValue><Modulus>w8oD7lBQrovytxepkGJ9vIBlEWZIeYTL+UrbDaLuw2uBGL8akcMnGKzj3D8fKaXejNzN3ls7AJfS7OsHb3+lJrCJUXVfshw/3nZumfYmNbsjQjU8o2g+zyU7ykIRZlcMRynmBFYsbvW4PZKLDaE7GuODiDamdYq5Fq3ZIhBTxLc2J5f50FHiQ1FBUW4oF+CM2QKr/dl1DdCAcWbnYKRTLvvxHwIc0LyfVEF8gQMKrrSoNAsDdqr2eUVuWYP0HH668H8Og59rFXEoXkzhIJiYLtVYJVmCfcyBG7UJwG/vFi2uDrvy0d64ItY88jniW2BSrWKZp7+kMNSpwc1gz73jrQ==</Modulus><Exponent>AQAB</Exponent><P>/fNdHmK365HZjlsRg61NBAW/ZAYGKm6psJMQMsSutpF2wVzFejA/cEMSjx3e6AVOko3aBznnOIEXKsyyvknXKPLV2JkoZ0B5T3SxHBEXPEc6Y3t4cKv7+zkyfhAJEbBvuR/PZO1lZjHSwd3lAO3VIIZ4gWjiG0cWp2djJzYnvEM=</P><Q>xV5+7dzTSgAW6oxPUx///0NRrVkfvxQTh/2QdlF9uHdP11GBUN9IjRUjczq0FJx/MeGFd/Oq3OKBqBn4I6FfP5INFspGGNan++GLK2K+fmsJYteuBRyJ068Yw0MY39T2XHRMTC9wnKonmFmrfkX4ixls7XlCl8Xm+Q2clE4i2U8=</Q><DP>leS+sv+75Zz6F++i/+Eb02L9HDH+E6+sE2BKsFytb2+e8/UpTr0JxN6iJr2P4822GgUGiztfQlfX79hRLMZy7GWhWa7VTVSeBgsvuwxPdbHpQe0QIxkwq5GQPx6B6+IDn/apuL3zGwYPi4TI9epr4T3eBSx+QXGNapQ4z11EyPc=</DP><DQ>eKfL8J2OjS6A0+HynF5zoRkGVXKmdalQR1I7fhlTQfGuXXL2Gvpk39qMUWURsYf6OgQkE7BiQ6Y0nQ9DIoUENViTp9r//y86gkDfUyaKTb4hfstbFsTbfQ0NllDuY+dMtDhkbC6UKTHcAsbOj+M2jdJ9RK9chmv1R0uK7R7XLwE=</DQ><InverseQ>0Zlo4C47H090YFujVjlQ4jRshqT5YsCpEvYf0Oy7ymCxV94WBmJIeYnfYcEp6HV19s8o+1KlHD/SKyhoeITyKaElqYELPheFz25XeXSSWA4+kKxaN4k75zRRHTcVJuwAfWrF+edXYbVpWXrEvMP/RJ1m65Ct/buYLJNpPmpibsY=</InverseQ><D>RYAQpSgde9hx8EyWBIrx11g8iFCmqXxaa8QGvnB4ESa4TPCJnfSIjFnTCPvfNAmNVrOK4MPBzhQW68MCgLHvDizcke34amFcyrt/x2d5aNllSrtbKyZ2JVIyRznss0dzNE/LNv7gBwNyw2ihs9ToBkN9DX1Y2aDE0ygjS9Q/6DQA754mVp4v70dL3Vmc4bw9uLsrB+r0Pgo6GbBFrGmis218V4gnHU5xsebhFjmwwyOy9r1r2Abc37TF+Z7UtmnV2B0zb1nuERiIfbRm2MzTksSZ3uQAPtk5qMaEP0jQGfTAS8dXi8vrjZvAgEJg0EtewYsNA9hcgTx0MK9PXdkwgQ==</D></RSAKeyValue>";

            //2048 private key
            string privateKey = RSATransUtil.RSAPrivateKeyDotNet2Java(privateXmlKey);

            var sourceString = "Hello world!";

            var rsaEncryptStringForPublicXmlKey = RSA.EncryptWithPublicXmlKey(sourceString, publicXmlKey);
            Console.WriteLine($"RSA Encrypt For Public XML Key:{rsaEncryptStringForPublicXmlKey}\n");

            var rsaDecryptStringForPublicXmlKey =
                RSA.DecryptWithPrivateXmlKey(rsaEncryptStringForPublicXmlKey, privateXmlKey);
            Console.WriteLine($"RSA Decrypt For Private XML Key:{rsaDecryptStringForPublicXmlKey}\n");


            var rsaEncryptStringForPrivateXmlKey = RSA.EncryptWithPrivateXmlKey(sourceString, privateXmlKey);
            Console.WriteLine($"RSA Encrypt For Private XML Key:{rsaEncryptStringForPrivateXmlKey}\n");

            var rsaDecryptStringForPrivateXmlKey =
                RSA.DecryptWithPrivateXmlKey(rsaEncryptStringForPrivateXmlKey, privateXmlKey);
            Console.WriteLine($"RSA Decrypt For Private XML Key:{rsaDecryptStringForPrivateXmlKey}\n");


            var rsaEncryptStringForPublicKey = RSA.EncryptWithPublicKey(sourceString, publicKey);
            Console.WriteLine($"RSA Encrypt For Public Key:{rsaEncryptStringForPublicKey}\n");

            var rsaDecryptStringForPublicKey = RSA.DecryptWithPrivateKey(rsaEncryptStringForPublicKey, privateKey);
            Console.WriteLine($"RSA Decrypt For Private  Key:{rsaDecryptStringForPublicKey}\n");


            var rsaEncryptStringForPrivateKey = RSA.EncryptWithPrivateKey(sourceString, privateKey);
            Console.WriteLine($"RSA Encrypt For Private Key:{rsaEncryptStringForPrivateKey}\n");

            var rsaDecryptStringForPrivateKey = RSA.DecryptWithPrivateKey(rsaEncryptStringForPrivateKey, privateKey);
            Console.WriteLine($"RSA Decrypt For Private XML Key:{rsaDecryptStringForPrivateKey}\n");


            var rsaSignString = RSA.Sign(sourceString, privateKey);
            Console.WriteLine($"RSA sign:{rsaSignString}\n");

            Console.WriteLine($"RSA verify sign:{RSA.Verify(sourceString, rsaSignString, publicKey)}\n");


            var rsaSignStringWithXmlKey = RSA.SignWithXmlKey(sourceString, privateXmlKey);
            Console.WriteLine($"RSA sign with xml key:{rsaSignStringWithXmlKey}\n");

            Console.WriteLine(
                $"RSA verify sign with xml key:{RSA.VerifyWithXmlKey(sourceString, rsaSignStringWithXmlKey, publicXmlKey)}\n");


            var pwd = "abc123456";
            var pbkdf2 = PBKDF2.HashPassword(pwd);
            Console.WriteLine($"PBKDF2 hash:{pbkdf2}");
            Console.WriteLine($"PBKDF2 verify:{PBKDF2.VerifyHashedPassword(pbkdf2, pwd)}");

            Console.ReadKey();
        }
    }
}