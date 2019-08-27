using System;
using System.Security.Cryptography;
using Utils.Encrypt;
using RSA = Utils.Encrypt.RSA;


namespace Sample
{
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


            //2048 public key
            string publicKey =
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnATf/6N22jNdRolMrdXmfIZXPat/MBXav7+5P8VZXd4nOnolHI0EKbqM2Dg9WkTxFsSLgId3PfAZLYg5Byu+gU/48W5AtURS4/8B2ehmAn6eXbvuycZDO9XSH8kfqzbdNisuPLVm8x3/uyEzrU20FA6Vc1J32lHPyfKWwNg5++fISXyLUvazNuYGedR8OzB7V+JLHBPs3woQBP065px/BTGAqPn6UoE6gtgsExe6Hpxbm0tVzTwO9TJtRvBk+QDCddGlydeDjjygNFs+pOzqp1nf/AhUDAEh0ln65UT5N3vcW0k+br1aM5sZD/ZueWh2TGBSCECAAqd8K2cALGHZ3QIDAQAB";
            //2048 private key
            string privateKey =
                "MIIEowIBAAKCAQEAnATf/6N22jNdRolMrdXmfIZXPat/MBXav7+5P8VZXd4nOnolHI0EKbqM2Dg9WkTxFsSLgId3PfAZLYg5Byu+gU/48W5AtURS4/8B2ehmAn6eXbvuycZDO9XSH8kfqzbdNisuPLVm8x3/uyEzrU20FA6Vc1J32lHPyfKWwNg5++fISXyLUvazNuYGedR8OzB7V+JLHBPs3woQBP065px/BTGAqPn6UoE6gtgsExe6Hpxbm0tVzTwO9TJtRvBk+QDCddGlydeDjjygNFs+pOzqp1nf/AhUDAEh0ln65UT5N3vcW0k+br1aM5sZD/ZueWh2TGBSCECAAqd8K2cALGHZ3QIDAQABAoIBABvmB0QIL+2Ot8QwMwT2tdNYlmsRqpmnnskg+Hg9yuAtJGihhNdZJABuOldDnzzwDQhcNvHRx3HM6EOrEz+EA/nNmh9Z7ro7MHNSmzsjAnK5v4nVXDq6eDVP49YJOd983QudpxP2ACXDHIKSylHYDjZz8SeA/KuOa5CaD3kGcT/pBwidWnoWoAjnG3wUmvjXaCqXkdcxYvN2OsUPsbSdUPu4rUz2arzMpsP0DXPWr0jMFn6DMikeCAvCyMxFB53tP5PHSdoLjoa/QdLfCcZ7qmKSoG+GSJNXweQYJWOMNGgzyuzUCwkrbi8UtdlussOvcXSCbPFV3DoS/5A/OtxBKaUCgYEA63cE1p2AUY/XOK6mD6ss1N81TOA0Ibtmx8byXHGZthwlqBoM/WHOUn9iCmpp5vIiiKLNDC00fOA9h/Pe/MiDeBDlBqLvw9O/RZlKVhDjzZq1UyjEwoqrKz6WfTFpDBCotyC7lqAZtabrYvk9Fl0YONaPgB3a4JhN74lLY7LeFp8CgYEAqaAmgatpW/Ycff2CjCmNtazpoAAUb75cbynemDJ+Jsx7CSvHLl7VCZkD8IKk4z20DmAnau6DlJOjgu8cEdwErJCB+632kbHYBP4t4e0QzkWGzBWtsEVdRq+BfLRToyHiLAJIGrp3WwIxNYzqJC1N4LU75MXgbBpvtTzLvnn+qgMCgYAN1DKjjCKCJ8mDGbbFCs+aPPW7axuEs6Xoq8WGKmHVsTeA9O64XusoKzUN2YwYtTXUAoO6aFlB0EWs22TIQdp+zbc1uZINVT1RkBwui9VlOOXXWXic2FoPMyDRf3pk7AGMp858nTCFW6VNbcfprVQD2o4Y/yfgsvE41T5pP5MNjwKBgDrIE/AFrbo/nHoQuwfFcqVNqZxXyr06k5+2O7w0a0EYxV5VPG4WUO9Fhnb3XxqcjGQa8C3/P7viOdyq7ehGfZwra9AC5hpxLfH0/4N2esdwkpjwvkMClqNjOJU1jHJQ0Kb9l20jxy7ToKf1EEK/LGi9hWbvJ6lus91zlwuIDTdvAoGBAMdgZmm5YdkbCQr7ec/0wJ80TYT7dhroVqTZ3kPSYunprUpI5l8KTyxW8ziwww8gb1POjIzyHfRYa9GrKTY/tMlgefcvZ+3zjbYrXprPi1lpFe6qj6y7S0Is0twYU4p8cKhW3RsAAnEvgJrq7JPQRvsYWmP1pZiriP2IQ0glBiAr";

            var sourceString = "Hello world!";
            var rsaEncryptString = RSA.Encrypt(sourceString, publicKey);
            Console.WriteLine($"RSA Encrypt:{rsaEncryptString}\n");
            Console.WriteLine($"RSA Decrypt:{RSA.Decrypt(rsaEncryptString, privateKey)}\n");

            var rsaSignString = RSA.Sign(sourceString, privateKey);
            Console.WriteLine($"RSA sign:{rsaSignString}\n");

            Console.WriteLine($"RSA verify sign:{RSA.Verify(sourceString, rsaSignString, publicKey)}\n");
            Console.ReadKey();
        }
    }
}
