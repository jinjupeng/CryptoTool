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
        /// SM4填充模式
        /// </summary>
        public enum PaddingMode
        {
            /// <summary>
            /// PKCS#7填充
            /// </summary>
            PKCS7,

            /// <summary>
            /// PKCS#5填充 (与PKCS#7类似，但针对8字节块)
            /// </summary>
            PKCS5,

            /// <summary>
            /// 不使用填充
            /// </summary>
            NoPadding
        }

        /// <summary>
        /// 格式类型枚举
        /// </summary>
        public enum FormatType
        {
            /// <summary>
            /// Base64编码
            /// </summary>
            Base64,
            
            /// <summary>
            /// 十六进制编码
            /// </summary>
            Hex,
            
            /// <summary>
            /// 文本格式(UTF-8)
            /// </summary>
            Text
        }

        #region 格式转换工具方法

        /// <summary>
        /// 根据格式类型将字符串转换为字节数组
        /// </summary>
        /// <param name="data">输入字符串</param>
        /// <param name="format">格式类型</param>
        /// <returns>字节数组</returns>
        public static byte[] ConvertToBytes(string data, FormatType format)
        {
            switch (format)
            {
                case FormatType.Base64:
                    return Convert.FromBase64String(data);
                case FormatType.Hex:
                    return HexToBytes(data);
                case FormatType.Text:
                    return Encoding.UTF8.GetBytes(data);
                default:
                    return Convert.FromBase64String(data);
            }
        }

        /// <summary>
        /// 根据格式类型将字节数组转换为字符串
        /// </summary>
        /// <param name="data">字节数组</param>
        /// <param name="format">格式类型</param>
        /// <returns>格式化的字符串</returns>
        public static string ConvertFromBytes(byte[] data, FormatType format)
        {
            switch (format)
            {
                case FormatType.Base64:
                    return Convert.ToBase64String(data);
                case FormatType.Hex:
                    return BytesToHex(data);
                case FormatType.Text:
                    return Encoding.UTF8.GetString(data);
                default:
                    return Convert.ToBase64String(data);
            }
        }

        /// <summary>
        /// 生成指定格式的随机SM4密钥
        /// </summary>
        /// <param name="format">输出格式</param>
        /// <returns>指定格式的随机密钥</returns>
        public static string GenerateKey(FormatType format = FormatType.Base64)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] key = new byte[KEY_SIZE];
                rng.GetBytes(key);
                return ConvertFromBytes(key, format);
            }
        }

        /// <summary>
        /// 生成指定格式的随机SM4初始向量
        /// </summary>
        /// <param name="format">输出格式</param>
        /// <returns>指定格式的随机初始向量</returns>
        public static string GenerateIV(FormatType format = FormatType.Base64)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] iv = new byte[BLOCK_SIZE];
                rng.GetBytes(iv);
                return ConvertFromBytes(iv, format);
            }
        }

        #endregion

        #region 支持多格式的加密解密方法

        /// <summary>
        /// SM4-ECB模式加密（支持多种格式）
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>指定格式的密文</returns>
        public static string EncryptEcbWithFormat(string plainText, string key, FormatType keyFormat, FormatType outputFormat, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            byte[] keyBytes = ConvertToBytes(key, keyFormat);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            if (keyBytes.Length != KEY_SIZE)
            {
                throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
            }

            byte[] cipherBytes = EncryptEcb(plainBytes, keyBytes, paddingMode);
            return ConvertFromBytes(cipherBytes, outputFormat);
        }

        /// <summary>
        /// SM4-ECB模式解密（支持多种格式）
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <param name="key">密钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>解密后的明文</returns>
        public static string DecryptEcbWithFormat(string cipherText, string key, FormatType keyFormat, FormatType inputFormat, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            byte[] keyBytes = ConvertToBytes(key, keyFormat);
            byte[] cipherBytes = ConvertToBytes(cipherText, inputFormat);

            if (keyBytes.Length != KEY_SIZE)
            {
                throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
            }

            byte[] plainBytes = DecryptEcb(cipherBytes, keyBytes, paddingMode);
            return Encoding.UTF8.GetString(plainBytes);
        }

        /// <summary>
        /// SM4-CBC模式加密（支持多种格式）
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始向量</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="ivFormat">IV格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>指定格式的密文</returns>
        public static string EncryptCbcWithFormat(string plainText, string key, string iv, FormatType keyFormat, FormatType ivFormat, FormatType outputFormat, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            byte[] keyBytes = ConvertToBytes(key, keyFormat);
            byte[] ivBytes = ConvertToBytes(iv, ivFormat);
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            if (keyBytes.Length != KEY_SIZE)
            {
                throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
            }

            if (ivBytes.Length != BLOCK_SIZE)
            {
                throw new ArgumentException($"初始向量必须为{BLOCK_SIZE}字节(128位)", nameof(iv));
            }

            byte[] cipherBytes = EncryptCbc(plainBytes, keyBytes, ivBytes, paddingMode);
            return ConvertFromBytes(cipherBytes, outputFormat);
        }

        /// <summary>
        /// SM4-CBC模式解密（支持多种格式）
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始向量</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="ivFormat">IV格式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>解密后的明文</returns>
        public static string DecryptCbcWithFormat(string cipherText, string key, string iv, FormatType keyFormat, FormatType ivFormat, FormatType inputFormat, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            byte[] keyBytes = ConvertToBytes(key, keyFormat);
            byte[] ivBytes = ConvertToBytes(iv, ivFormat);
            byte[] cipherBytes = ConvertToBytes(cipherText, inputFormat);

            if (keyBytes.Length != KEY_SIZE)
            {
                throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
            }

            if (ivBytes.Length != BLOCK_SIZE)
            {
                throw new ArgumentException($"初始向量必须为{BLOCK_SIZE}字节(128位)", nameof(iv));
            }

            byte[] plainBytes = DecryptCbc(cipherBytes, keyBytes, ivBytes, paddingMode);
            return Encoding.UTF8.GetString(plainBytes);
        }

        #endregion

        // 原有的方法保持不变以保证向后兼容
        #region 原有的加密解密方法（保持向后兼容）

        /// <summary>
        /// SM4-ECB模式加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥(16字节)</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <param name="paddingMode">填充模式，默认PKCS7</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptEcb(string plainText, string key, Encoding encoding = null, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] keyBytes = encoding.GetBytes(key);
            byte[] plainBytes = encoding.GetBytes(plainText);

            if (keyBytes.Length != KEY_SIZE)
            {
                throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
            }

            byte[] cipherBytes = EncryptEcb(plainBytes, keyBytes, paddingMode);
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// SM4-ECB模式解密
        /// </summary>
        /// <param name="cipherText">Base64编码的密文</param>
        /// <param name="key">密钥(16字节)</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <param name="paddingMode">填充模式，默认PKCS7</param>
        /// <returns>解密后的明文</returns>
        public static string DecryptEcb(string cipherText, string key, Encoding encoding = null, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] keyBytes = encoding.GetBytes(key);
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            if (keyBytes.Length != KEY_SIZE)
            {
                throw new ArgumentException($"SM4密钥必须为{KEY_SIZE}字节(128位)", nameof(key));
            }

            byte[] plainBytes = DecryptEcb(cipherBytes, keyBytes, paddingMode);
            return encoding.GetString(plainBytes);
        }

        /// <summary>
        /// SM4-CBC模式加密
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥(16字节)</param>
        /// <param name="iv">初始向量(16字节)</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <param name="paddingMode">填充模式，默认PKCS7</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptCbc(string plainText, string key, string iv, Encoding encoding = null, PaddingMode paddingMode = PaddingMode.PKCS7)
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

            byte[] cipherBytes = EncryptCbc(plainBytes, keyBytes, ivBytes, paddingMode);
            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// SM4-CBC模式解密
        /// </summary>
        /// <param name="cipherText">Base64编码的密文</param>
        /// <param name="key">密钥(16字节)</param>
        /// <param name="iv">初始向量(16字节)</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <param name="paddingMode">填充模式，默认PKCS7</param>
        /// <returns>解密后的明文</returns>
        public static string DecryptCbc(string cipherText, string key, string iv, Encoding encoding = null, PaddingMode paddingMode = PaddingMode.PKCS7)
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

            byte[] plainBytes = DecryptCbc(cipherBytes, keyBytes, ivBytes, paddingMode);
            return encoding.GetString(plainBytes);
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

        #endregion

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
        public static string BytesToHex(byte[] bytes, bool isUpper = true)
        {
            string hex = Hex.ToHexString(bytes);
            return isUpper ? hex.ToUpper() : hex;
        }

        #region 内部实现方法

        /// <summary>
        /// 获取指定的填充器
        /// </summary>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>IBlockCipherPadding 实例或 null (无填充)</returns>
        private static IBlockCipherPadding GetPadding(PaddingMode paddingMode)
        {
            switch (paddingMode)
            {
                case PaddingMode.PKCS7:
                    return new Pkcs7Padding();
                case PaddingMode.PKCS5:
                    // BouncyCastle中没有单独的PKCS5Padding实现，PKCS5本质上是针对8字节块的PKCS7
                    // 在SM4中块大小为16字节，因此这里也使用PKCS7填充
                    return new Pkcs7Padding();
                case PaddingMode.NoPadding:
                    return null;
                default:
                    return new Pkcs7Padding(); // 默认使用PKCS7
            }
        }

        /// <summary>
        /// 创建块密码
        /// </summary>
        /// <param name="engine">加密引擎</param>
        /// <param name="paddingMode">填充模式</param>
        /// <param name="isEncryption">是否为加密模式</param>
        /// <returns>缓冲块密码</returns>
        private static IBufferedCipher CreateCipher(IBlockCipher engine, PaddingMode paddingMode, bool isEncryption)
        {
            IBlockCipherPadding padding = GetPadding(paddingMode);

            // 如果选择了无填充，使用BufferedBlockCipher而不是PaddedBufferedBlockCipher
            if (paddingMode == PaddingMode.NoPadding)
            {
                BufferedBlockCipher cipher = new BufferedBlockCipher(engine);
                cipher.Init(isEncryption, new KeyParameter(new byte[KEY_SIZE])); // 临时初始化以获取正确的类型
                return cipher;
            }
            else
            {
                PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(engine, padding);
                cipher.Init(isEncryption, new KeyParameter(new byte[KEY_SIZE])); // 临时初始化以获取正确的类型
                return cipher;
            }
        }

        /// <summary>
        /// 处理密码操作
        /// </summary>
        /// <param name="cipher">密码实例</param>
        /// <param name="data">输入数据</param>
        /// <param name="parameters">密码参数</param>
        /// <param name="isEncryption">是否为加密操作</param>
        /// <returns>处理后的数据</returns>
        private static byte[] ProcessCipher(IBufferedCipher cipher, byte[] data, ICipherParameters parameters, bool isEncryption)
        {
            cipher.Init(isEncryption, parameters);

            // 验证无填充模式下数据长度
            if (cipher is BufferedBlockCipher && !(cipher is PaddedBufferedBlockCipher) && isEncryption)
            {
                if (data.Length % BLOCK_SIZE != 0)
                {
                    throw new ArgumentException($"使用无填充模式时，数据长度必须是{BLOCK_SIZE}的整数倍");
                }
            }

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
        /// SM4-ECB模式加密
        /// </summary>
        /// <param name="data">明文字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>密文字节数组</returns>
        public static byte[] EncryptEcb(byte[] data, byte[] key, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            // 创建SM4引擎
            SM4Engine engine = new SM4Engine();

            // 创建适当的密码实例
            IBufferedCipher cipher = CreateCipher(engine, paddingMode, true);

            // 创建加密参数
            KeyParameter keyParam = new KeyParameter(key);

            // 处理加密
            return ProcessCipher(cipher, data, keyParam, true);
        }

        /// <summary>
        /// SM4-ECB模式解密
        /// </summary>
        /// <param name="data">密文字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>明文字节数组</returns>
        public static byte[] DecryptEcb(byte[] data, byte[] key, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            // 创建SM4引擎
            SM4Engine engine = new SM4Engine();

            // 创建适当的密码实例
            IBufferedCipher cipher = CreateCipher(engine, paddingMode, false);

            // 创建解密参数
            KeyParameter keyParam = new KeyParameter(key);

            // 处理解密
            return ProcessCipher(cipher, data, keyParam, false);
        }

        /// <summary>
        /// SM4-CBC模式加密
        /// </summary>
        /// <param name="data">明文字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <param name="iv">初始向量字节数组</param>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>密文字节数组</returns>
        public static byte[] EncryptCbc(byte[] data, byte[] key, byte[] iv, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            // 创建SM4引擎
            SM4Engine engine = new SM4Engine();

            // 创建CBC模式的块密码
            CbcBlockCipher cbcBlockCipher = new CbcBlockCipher(engine);

            // 创建适当的密码实例
            IBufferedCipher cipher;
            if (paddingMode == PaddingMode.NoPadding)
            {
                cipher = new BufferedBlockCipher(cbcBlockCipher);
            }
            else
            {
                IBlockCipherPadding padding = GetPadding(paddingMode);
                cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, padding);
            }

            // 创建加密参数，包括密钥和IV
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);

            // 处理加密
            return ProcessCipher(cipher, data, parameters, true);
        }

        /// <summary>
        /// SM4-CBC模式解密
        /// </summary>
        /// <param name="data">密文字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <param name="iv">初始向量字节数组</param>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>明文字节数组</returns>
        public static byte[] DecryptCbc(byte[] data, byte[] key, byte[] iv, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            // 创建SM4引擎
            SM4Engine engine = new SM4Engine();

            // 创建CBC模式的块密码
            CbcBlockCipher cbcBlockCipher = new CbcBlockCipher(engine);

            // 创建适当的密码实例
            IBufferedCipher cipher;
            if (paddingMode == PaddingMode.NoPadding)
            {
                cipher = new BufferedBlockCipher(cbcBlockCipher);
            }
            else
            {
                IBlockCipherPadding padding = GetPadding(paddingMode);
                cipher = new PaddedBufferedBlockCipher(cbcBlockCipher, padding);
            }

            // 创建解密参数，包括密钥和IV
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key), iv);

            // 处理解密
            return ProcessCipher(cipher, data, parameters, false);
        }

        #endregion
    }
}
