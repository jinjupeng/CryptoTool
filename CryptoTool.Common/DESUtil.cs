using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Common
{
    public class DESUtil
    {
        #region DES
        /// <summary>
        /// 加密方法
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string EncryptByDES(string input, string key)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input); //Encoding.UTF8.GetBytes(input);
            byte[] keyBytes = ASCIIEncoding.UTF8.GetBytes(key);
            byte[] encryptBytes = EncryptByDES(inputBytes, keyBytes, keyBytes);
            //string result = Encoding.UTF8.GetString(encryptBytes); //无法解码,其加密结果中文出现乱码：d\"�e����(��uπ�W��-��,_�\nJn7 
            //原因：如果明文为中文，UTF8编码两个字节标识一个中文字符，但是加密后，两个字节密文，不一定还是中文字符。
            using (DES des = new DESCryptoServiceProvider())
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cs))
                        {
                            writer.Write(inputBytes);
                        }
                    }
                }
            }

            string result = Convert.ToBase64String(encryptBytes);

            return result;
        }
        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="inputBytes">输入byte数组</param>
        /// <param name="key">密钥，只能是英文字母或数字</param>
        /// <param name="IV">偏移向量</param>
        /// <returns></returns>
        public static byte[] EncryptByDES(byte[] inputBytes, byte[] key, byte[] IV)
        {
            DES des = new DESCryptoServiceProvider();
            //建立加密对象的密钥和偏移量
            des.Key = key;
            des.IV = IV;
            string result = string.Empty;

            //1、如果通过CryptoStreamMode.Write方式进行加密，然后CryptoStreamMode.Read方式进行解密，解密成功。
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(inputBytes, 0, inputBytes.Length);
                }
                return ms.ToArray();
            }
            //2、如果通过CryptoStreamMode.Write方式进行加密，然后再用CryptoStreamMode.Write方式进行解密，可以得到正确结果
            //3、如果通过CryptoStreamMode.Read方式进行加密，然后再用CryptoStreamMode.Read方式进行解密，无法解密，Error：要解密的数据的长度无效。
            //4、如果通过CryptoStreamMode.Read方式进行加密，然后再用CryptoStreamMode.Write方式进行解密,无法解密，Error：要解密的数据的长度无效。
            //using (MemoryStream ms = new MemoryStream(inputBytes))
            //{
            //    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Read))
            //    {
            //        using (StreamReader reader = new StreamReader(cs))
            //        {
            //            result = reader.ReadToEnd();
            //            return Encoding.UTF8.GetBytes(result);
            //        }
            //    }
            //}
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string DecryptByDES(string input, string key)
        {
            //UTF8无法解密，Error: 要解密的数据的长度无效。
            //byte[] inputBytes = Encoding.UTF8.GetBytes(input);//UTF8乱码，见加密算法
            byte[] inputBytes = Convert.FromBase64String(input);

            byte[] keyBytes = ASCIIEncoding.UTF8.GetBytes(key);
            byte[] resultBytes = DecryptByDES(inputBytes, keyBytes, keyBytes);

            string result = Encoding.UTF8.GetString(resultBytes);

            return result;
        }
        /// <summary>
        /// 解密方法
        /// </summary>
        /// <param name="inputBytes"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public static byte[] DecryptByDES(byte[] inputBytes, byte[] key, byte[] iv)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            //建立加密对象的密钥和偏移量，此值重要，不能修改
            des.Key = key;
            des.IV = iv;

            //通过write方式解密
            //using (MemoryStream ms = new MemoryStream())
            //{
            //    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
            //    {
            //        cs.Write(inputBytes, 0, inputBytes.Length);
            //    }
            //    return ms.ToArray();
            //}

            //通过read方式解密
            using (MemoryStream ms = new MemoryStream(inputBytes))
            {
                using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cs))
                    {
                        string result = reader.ReadToEnd();
                        return Encoding.UTF8.GetBytes(result);
                    }
                }
            }

            //错误写法,注意哪个是输出流的位置，如果范围ms，与原文不一致。
            //using (MemoryStream ms = new MemoryStream(inputBytes))
            //{
            //    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Read))
            //    {
            //        cs.Read(inputBytes, 0, inputBytes.Length);
            //    }
            //    return ms.ToArray();
            //}
        }

        /// <summary>
        /// 加密字符串
        /// </summary>
        /// <param name="input"></param>
        /// <param name="sKey"></param>
        /// <returns></returns>
        public static string EncryptString(string input, string sKey)
        {
            byte[] data = Encoding.UTF8.GetBytes(input);
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
                des.IV = ASCIIEncoding.ASCII.GetBytes(sKey);
                ICryptoTransform desencrypt = des.CreateEncryptor();
                byte[] result = desencrypt.TransformFinalBlock(data, 0, data.Length);
                return BitConverter.ToString(result);
            }
        }
        /// <summary>
        /// 解密字符串
        /// </summary>
        /// <param name="input"></param>
        /// <param name="sKey"></param>
        /// <returns></returns>
        public static string DecryptString(string input, string sKey)
        {
            string[] sInput = input.Split("-".ToCharArray());
            byte[] data = new byte[sInput.Length];
            for (int i = 0; i < sInput.Length; i++)
            {
                data[i] = byte.Parse(sInput[i], NumberStyles.HexNumber);
            }
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = ASCIIEncoding.ASCII.GetBytes(sKey);
                des.IV = ASCIIEncoding.ASCII.GetBytes(sKey);
                ICryptoTransform desencrypt = des.CreateDecryptor();
                byte[] result = desencrypt.TransformFinalBlock(data, 0, data.Length);
                return Encoding.UTF8.GetString(result);
            }
        }
        #endregion
    }
}
