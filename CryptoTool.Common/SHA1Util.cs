using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Common
{
    public class SHA1Util
    {
        #region SHA1
        /// <summary>
        /// SHA1加密
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string EncryptBySHA1(string input)
        {
            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] bytes = Encoding.Unicode.GetBytes(input);
            byte[] result = sha.ComputeHash(bytes);
            return Convert.ToBase64String(result); // BitConverter.ToString(result);
        }
        #endregion
    }
}
