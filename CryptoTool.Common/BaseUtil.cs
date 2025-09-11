using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CryptoTool.Common
{
    public class BaseUtil
    {
        // 定义可读字符集：大小写字母、数字以及特殊符号
        private const string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";



        /// <summary>
        /// 生成指定长度的可读字符串（包含字母、数字和特殊符号）
        /// </summary>
        /// <param name="length">字符串长度</param>
        /// <returns>可读字符串</returns>
        public static string GenerateRandomString(int length)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var result = new StringBuilder(length);
                var buffer = new byte[4]; // 用于生成随机数

                for (int i = 0; i < length; i++)
                {
                    rng.GetBytes(buffer);
                    var randomValue = BitConverter.ToUInt32(buffer, 0);
                    var charIndex = randomValue % charset.Length;
                    result.Append(charset[(int)charIndex]);
                }

                return result.ToString();
            }
        }

        /// <summary>
        /// 将字节数组转换为16进制字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <param name="upperCase">是否返回大写，默认false（小写）</param>
        /// <returns>16进制字符串</returns>
        public static string ConvertToHexString(byte[] bytes, bool upperCase = false)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            string format = upperCase ? "X2" : "x2";

            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString(format));
            }

            return sb.ToString();
        }

        /// <summary>
        /// 将16进制字符串转换为字节数组
        /// </summary>
        /// <param name="hexString">16进制字符串</param>
        /// <returns>字节数组</returns>
        public static byte[] ConvertFromHexString(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentException("16进制字符串不能为空", nameof(hexString));

            if (hexString.Length % 2 != 0)
                throw new ArgumentException("16进制字符串长度必须为偶数", nameof(hexString));

            byte[] result = new byte[hexString.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return result;
        }
    }
}
