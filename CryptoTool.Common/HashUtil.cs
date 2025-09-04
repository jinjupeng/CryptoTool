using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoTool.Common
{
    public class HashUtil
    {
        /// <summary>
        /// 获取文件Hash值
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static string GetHashCode(string filePath, string hashAlgo = "MD5")
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                FileStream file = new FileStream(filePath, FileMode.Open);
                HashAlgorithm hashAlgorithm = HashAlgorithm.Create(hashAlgo);
                byte[] retVal = hashAlgorithm.ComputeHash(file);
                file.Close();
                for (int i = 0; i < retVal.Length; i++)
                {
                    sb.Append(retVal[i].ToString("x2"));
                }
            }
            catch
            {
                sb.Append("");
            }
            return sb.ToString();
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] GetBytes(string input)
        {
            string[] sInput = input.Split("-".ToCharArray());
            byte[] inputBytes = new byte[sInput.Length];
            for (int i = 0; i < sInput.Length; i++)
            {
                inputBytes[i] = byte.Parse(sInput[i], NumberStyles.HexNumber);
            }
            return inputBytes;
        }
    }
}
