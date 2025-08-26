using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptoTool.Common.GM
{
    /// <summary>
    /// 使用BouncyCastle实现的SM4国密算法工具类
    /// </summary>
    public class SM4Util
    {
        private const int KEY_SIZE = 16; // SM4密钥长度为128位(16字节)
        private const int BLOCK_SIZE = 16; // SM4分组长度为128位(16字节)

        /// <summary>
        /// SM4-ECB模式加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥(16字节)</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptEcb(string plainText, string key, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] keyBytes = encoding.GetBytes(key);
            byte[] plainBytes = encoding.GetBytes(plainText);

            if (keyBytes.Length != KEY_SIZE)
            {
                throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
            }

            byte[] cipherBytes = EncryptEcb(plainBytes, keyBytes);
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// SM4-ECB模式解密
        /// </summary>
        /// <param name="cipherText">Base64编码的密文</param>
        /// <param name="key">密钥(16字节)</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>解密后的明文</returns>
        public static string DecryptEcb(string cipherText, string key, Encoding encoding = null)
        {
            try
            {
                encoding = encoding ?? Encoding.UTF8;
                byte[] keyBytes = encoding.GetBytes(key);
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                if (keyBytes.Length != KEY_SIZE)
                {
                    throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
                }

                byte[] plainBytes = DecryptEcb(cipherBytes, keyBytes);
                return encoding.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("SM4解密失败", ex);
            }
        }

        /// <summary>
        /// SM4-CBC模式加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥(16字节)</param>
        /// <param name="iv">初始向量(16字节)</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptCbc(string plainText, string key, string iv, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] keyBytes = encoding.GetBytes(key);
            byte[] ivBytes = encoding.GetBytes(iv);
            byte[] plainBytes = encoding.GetBytes(plainText);

            if (keyBytes.Length != KEY_SIZE)
            {
                throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
            }

            if (ivBytes.Length != BLOCK_SIZE)
            {
                throw new ArgumentException($"初始向量必须为{BLOCK_SIZE}字节(128位)", nameof(iv));
            }

            byte[] cipherBytes = EncryptCbc(plainBytes, keyBytes, ivBytes);
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// SM4-CBC模式解密
        /// </summary>
        /// <param name="cipherText">Base64编码的密文</param>
        /// <param name="key">密钥(16字节)</param>
        /// <param name="iv">初始向量(16字节)</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>解密后的明文</returns>
        public static string DecryptCbc(string cipherText, string key, string iv, Encoding encoding = null)
        {
            try
            {
                encoding = encoding ?? Encoding.UTF8;
                byte[] keyBytes = encoding.GetBytes(key);
                byte[] ivBytes = encoding.GetBytes(iv);
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                if (keyBytes.Length != KEY_SIZE)
                {
                    throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
                }

                if (ivBytes.Length != BLOCK_SIZE)
                {
                    throw new ArgumentException($"初始向量必须为{BLOCK_SIZE}字节(128位)", nameof(iv));
                }

                byte[] plainBytes = DecryptCbc(cipherBytes, keyBytes, ivBytes);
                return encoding.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("SM4 CBC模式解密失败", ex);
            }
        }

        /// <summary>
        /// 生成随机SM4密钥
        /// </summary>
        /// <returns>Base64编码的随机密钥</returns>
        public static string GenerateKey()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[KEY_SIZE];
                rng.GetBytes(key);
                return Convert.ToBase64String(key);
            }
        }

        /// <summary>
        /// 生成随机SM4初始向量
        /// </summary>
        /// <returns>Base64编码的随机初始向量</returns>
        public static string GenerateIV()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] iv = new byte[BLOCK_SIZE];
                rng.GetBytes(iv);
                return Convert.ToBase64String(iv);
            }
        }

        /// <summary>
        /// 将16进制字符串转换为字节数组
        /// </summary>
        /// <param name="hexString">16进制字符串</param>
        /// <returns>字节数组</returns>
        public static byte[] HexToBytes(string hexString)
        {
            return Hex.Decode(hexString);
        }

        /// <summary>
        /// 将字节数组转换为16进制字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <returns>16进制字符串</returns>
        public static string BytesToHex(byte[] bytes)
        {
            return Hex.ToHexString(bytes).ToUpper();
        }

        #region 内部实现方法

        /// <summary>
        /// SM4-ECB模式加密
        /// </summary>
        /// <param name="data">明文字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <returns>密文字节数组</returns>
        private static byte[] EncryptEcb(byte[] data, byte[] key)
        {
            // 创建SM4引擎
            SM4Engine engine = new SM4Engine();

            // 创建加密参数
            KeyParameter keyParam = new KeyParameter(key);

            // 使用PaddedBufferedBlockCipher进行ECB模式加密，默认使用PKCS7填充
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
            cipher.Init(true, keyParam); // true表示加密模式

            // 计算输出缓冲区大小，包括可能的填充
            byte[] output = new byte[cipher.GetOutputSize(data.Length)];

            // 处理数据
            int length = cipher.ProcessBytes(data, 0, data.Length, output, 0);

            // 处理最后的数据块和填充
            length += cipher.DoFinal(output, length);

            // 如果输出长度不等于输出缓冲区长度，则创建一个新的数组
            if (length != output.Length)
            {
                byte[] temp = new byte[length];
                Array.Copy(output, 0, temp, 0, length);
                return temp;
            }

            return output;
        }

        /// <summary>
        /// SM4-ECB模式解密
        /// </summary>
        /// <param name="data">密文字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <returns>明文字节数组</returns>
        private static byte[] DecryptEcb(byte[] data, byte[] key)
        {
            // 创建SM4引擎
            SM4Engine engine = new SM4Engine();

            // 创建解密参数
            KeyParameter keyParam = new KeyParameter(key);

            // 使用PaddedBufferedBlockCipher进行ECB模式解密，默认使用PKCS7填充
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine);
            cipher.Init(false, keyParam); // false表示解密模式

            // 计算输出缓冲区大小
            byte[] output = new byte[cipher.GetOutputSize(data.Length)];

            // 处理数据
            int length = cipher.ProcessBytes(data, 0, data.Length, output, 0);

            // 处理最后的数据块和填充
            length += cipher.DoFinal(output, length);

            // 如果输出长度不等于输出缓冲区长度，则创建一个新的数组
            if (length != output.Length)
            {
                byte[] temp = new byte[length];
                Array.Copy(output, 0, temp, 0, length);
                return temp;
            }

            return output;
        }

        /// <summary>
        /// SM4-CBC模式加密
        /// </summary>
        /// <param name="data">明文字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <param name="iv">初始向量字节数组</param>
        /// <returns>密文字节数组</returns>
        private static byte[] EncryptCbc(byte[] data, byte[] key, byte[] iv)
        {
            // 创建SM4引擎
            SM4Engine engine = new SM4Engine();

            // 创建加密参数，包括密钥和IV
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);

            // 使用CBC模式
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
            cipher.Init(true, parameters); // true表示加密模式

            // 计算输出缓冲区大小，包括可能的填充
            byte[] output = new byte[cipher.GetOutputSize(data.Length)];

            // 处理数据
            int length = cipher.ProcessBytes(data, 0, data.Length, output, 0);

            // 处理最后的数据块和填充
            length += cipher.DoFinal(output, length);

            // 如果输出长度不等于输出缓冲区长度，则创建一个新的数组
            if (length != output.Length)
            {
                byte[] temp = new byte[length];
                Array.Copy(output, 0, temp, 0, length);
                return temp;
            }

            return output;
        }

        /// <summary>
        /// SM4-CBC模式解密
        /// </summary>
        /// <param name="data">密文字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <param name="iv">初始向量字节数组</param>
        /// <returns>明文字节数组</returns>
        private static byte[] DecryptCbc(byte[] data, byte[] key, byte[] iv)
        {
            // 创建SM4引擎
            SM4Engine engine = new SM4Engine();

            // 创建解密参数，包括密钥和IV
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);

            // 使用CBC模式
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
            cipher.Init(false, parameters); // false表示解密模式

            // 计算输出缓冲区大小
            byte[] output = new byte[cipher.GetOutputSize(data.Length)];

            // 处理数据
            int length = cipher.ProcessBytes(data, 0, data.Length, output, 0);

            // 处理最后的数据块和填充
            length += cipher.DoFinal(output, length);

            // 如果输出长度不等于输出缓冲区长度，则创建一个新的数组
            if (length != output.Length)
            {
                byte[] temp = new byte[length];
                Array.Copy(output, 0, temp, 0, length);
                return temp;
            }

            return output;
        }

        #endregion
    }
}
