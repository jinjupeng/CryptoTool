using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Common
{
    public class MD5Util
    {
        #region MD5

        /// <summary>
        /// MD5加密为32字符长度的16进制字符串
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string EncryptByMD5(string input)
        {
            MD5 md5Hasher = MD5.Create();
            byte[] data = md5Hasher.ComputeHash(Encoding.UTF8.GetBytes(input));

            StringBuilder sBuilder = new StringBuilder();
            //将每个字节转为16进制
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            return sBuilder.ToString();
        }
        #endregion



        /// <summary>
        /// 生成appId
        /// </summary>
        /// <returns></returns>
        public static string GetAppId()
        {
            // https://stackoverflow.com/questions/14412132/whats-the-best-approach-for-generating-a-new-api-key
            var key = new byte[32];
            using (var generator = RandomNumberGenerator.Create())
                generator.GetBytes(key);
            string apiKey = Convert.ToBase64String(key);
            return apiKey;
        }

        /// <summary>
        /// 生成appSecret
        /// </summary>
        /// <returns></returns>
        public static string GetAppSecret()
        {
            return "";
        }
    }
}
