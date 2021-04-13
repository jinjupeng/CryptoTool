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
    }
}
