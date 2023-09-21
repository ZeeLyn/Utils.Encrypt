using System;
using System.Text;

namespace Utils.Encrypt
{
    public static class RandomString
    {
        private static readonly char[] Constant =
        {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
            'v', 'w', 'x', 'y', 'z',
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
            'V', 'W', 'X', 'Y', 'Z'
        };

        public static string Generate(int length, bool hasNumber = true, bool matchCase = true)
        {
            var builder = new StringBuilder();
            var random = new Random(DateTime.Now.Ticks.GetHashCode());
            for (var i = 0; i < length; i++)
            {
                builder.Append(Constant[random.Next(hasNumber ? 0 : 10, matchCase ? 62 : 36)]);
            }

            return builder.ToString();
        }
    }
}