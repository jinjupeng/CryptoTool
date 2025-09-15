using CryptoTool.Algorithm.Factory;
using CryptoTool.Algorithm.Utils;
using System.Threading.Tasks;

namespace CryptoTool.Algorithm
{
    /// <summary>
    /// 加密工具主类
    /// </summary>
    public static class CryptoTool
    {
        /// <summary>
        /// 获取支持的算法列表
        /// </summary>
        public static string[] SupportedAlgorithms => new[]
        {
            "RSA", "AES", "DES", "MD5", "SM2", "SM3", "SM4"
        };

        #region 对称加密

        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>加密后的数据</returns>
        public static byte[] AesEncrypt(byte[] data, byte[] key, byte[]? iv = null)
        {
            var aes = CryptoFactory.CreateAes();
            return aes.Encrypt(data, key, iv);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>解密后的数据</returns>
        public static byte[] AesDecrypt(byte[] encryptedData, byte[] key, byte[]? iv = null)
        {
            var aes = CryptoFactory.CreateAes();
            return aes.Decrypt(encryptedData, key, iv);
        }

        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>加密后的数据</returns>
        public static byte[] DesEncrypt(byte[] data, byte[] key, byte[]? iv = null)
        {
            var des = CryptoFactory.CreateDes();
            return des.Encrypt(data, key, iv);
        }

        /// <summary>
        /// DES解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>解密后的数据</returns>
        public static byte[] DesDecrypt(byte[] encryptedData, byte[] key, byte[]? iv = null)
        {
            var des = CryptoFactory.CreateDes();
            return des.Decrypt(encryptedData, key, iv);
        }

        /// <summary>
        /// SM4加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>加密后的数据</returns>
        public static byte[] Sm4Encrypt(byte[] data, byte[] key, byte[]? iv = null)
        {
            var sm4 = CryptoFactory.CreateSm4();
            return sm4.Encrypt(data, key, iv);
        }

        /// <summary>
        /// SM4解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>解密后的数据</returns>
        public static byte[] Sm4Decrypt(byte[] encryptedData, byte[] key, byte[]? iv = null)
        {
            var sm4 = CryptoFactory.CreateSm4();
            return sm4.Decrypt(encryptedData, key, iv);
        }

        #endregion

        #region 非对称加密

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>加密后的数据</returns>
        public static byte[] RsaEncrypt(byte[] data, byte[] publicKey)
        {
            var rsa = CryptoFactory.CreateRsa();
            return rsa.Encrypt(data, publicKey);
        }

        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>解密后的数据</returns>
        public static byte[] RsaDecrypt(byte[] encryptedData, byte[] privateKey)
        {
            var rsa = CryptoFactory.CreateRsa();
            return rsa.Decrypt(encryptedData, privateKey);
        }

        /// <summary>
        /// RSA生成密钥对
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>密钥对</returns>
        public static (byte[] PublicKey, byte[] PrivateKey) RsaGenerateKeyPair(int keySize = 2048)
        {
            var rsa = CryptoFactory.CreateRsa(keySize);
            return rsa.GenerateKeyPair();
        }

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>签名数据</returns>
        public static byte[] RsaSign(byte[] data, byte[] privateKey)
        {
            var rsa = CryptoFactory.CreateRsa();
            return rsa.Sign(data, privateKey);
        }

        /// <summary>
        /// RSA验证签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>验证结果</returns>
        public static bool RsaVerifySignature(byte[] data, byte[] signature, byte[] publicKey)
        {
            var rsa = CryptoFactory.CreateRsa();
            return rsa.VerifySign(data, signature, publicKey);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>加密后的数据</returns>
        public static byte[] Sm2Encrypt(byte[] data, byte[] publicKey)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.Encrypt(data, publicKey);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>解密后的数据</returns>
        public static byte[] Sm2Decrypt(byte[] encryptedData, byte[] privateKey)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.Decrypt(encryptedData, privateKey);
        }

        /// <summary>
        /// SM2生成密钥对
        /// </summary>
        /// <returns>密钥对</returns>
        public static (byte[] PublicKey, byte[] PrivateKey) Sm2GenerateKeyPair()
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.GenerateKeyPair();
        }

        /// <summary>
        /// SM2签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>签名数据</returns>
        public static byte[] Sm2Sign(byte[] data, byte[] privateKey)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.Sign(data, privateKey);
        }

        /// <summary>
        /// SM2验证签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>验证结果</returns>
        public static bool Sm2VerifySignature(byte[] data, byte[] signature, byte[] publicKey)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.VerifySign(data, signature, publicKey);
        }

        /// <summary>
        /// SM2密文格式转换：C1C2C3转C1C3C2
        /// </summary>
        /// <param name="c1c2c3Data">C1C2C3格式密文</param>
        /// <returns>C1C3C2格式密文</returns>
        public static byte[] Sm2ConvertC1C2C3ToC1C3C2(byte[] c1c2c3Data)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.C1C2C3ToC1C3C2(c1c2c3Data);
        }

        /// <summary>
        /// SM2密文格式转换：C1C3C2转C1C2C3
        /// </summary>
        /// <param name="c1c3c2Data">C1C3C2格式密文</param>
        /// <returns>C1C2C3格式密文</returns>
        public static byte[] Sm2ConvertC1C3C2ToC1C2C3(byte[] c1c3c2Data)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.C1C3C2ToC1C2C3(c1c3c2Data);
        }

        /// <summary>
        /// SM2检测密文格式
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <returns>密文格式</returns>
        public static Algorithms.SM2.SM2CipherFormat Sm2DetectCipherFormat(byte[] cipherData)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.DetectCipherFormat(cipherData);
        }

        /// <summary>
        /// SM2验证密文数据完整性
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <param name="expectedFormat">期望的格式</param>
        /// <returns>是否有效</returns>
        public static bool Sm2ValidateCipherData(byte[] cipherData, Algorithms.SM2.SM2CipherFormat expectedFormat)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.ValidateCipherData(cipherData, expectedFormat);
        }

        /// <summary>
        /// SM2获取密文组件信息
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <returns>组件信息</returns>
        public static Algorithms.SM2.SM2CipherComponentInfo Sm2GetCipherComponentInfo(byte[] cipherData)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return sm2.GetCipherComponentInfo(cipherData);
        }

        #endregion

        #region 哈希算法

        /// <summary>
        /// MD5哈希
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <returns>哈希值</returns>
        public static byte[] Md5Hash(byte[] data)
        {
            var md5 = CryptoFactory.CreateMd5();
            return md5.ComputeHash(data);
        }

        /// <summary>
        /// MD5哈希（十六进制字符串）
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>哈希值（十六进制字符串）</returns>
        public static string Md5HashString(byte[] data, bool upperCase = false)
        {
            var md5 = CryptoFactory.CreateMd5();
            return md5.ComputeHashString(data, upperCase);
        }

        /// <summary>
        /// SM3哈希
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <returns>哈希值</returns>
        public static byte[] Sm3Hash(byte[] data)
        {
            var sm3 = CryptoFactory.CreateSm3();
            return sm3.ComputeHash(data);
        }

        /// <summary>
        /// SM3哈希（十六进制字符串）
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>哈希值（十六进制字符串）</returns>
        public static string Sm3HashString(byte[] data, bool upperCase = false)
        {
            var sm3 = CryptoFactory.CreateSm3();
            return sm3.ComputeHashString(data, upperCase);
        }

        #endregion

        #region 工具方法

        /// <summary>
        /// 生成随机密钥
        /// </summary>
        /// <param name="keySize">密钥长度（位）</param>
        /// <returns>随机密钥</returns>
        public static byte[] GenerateRandomKey(int keySize)
        {
            return StringUtil.GenerateRandomKey(keySize);
        }

        /// <summary>
        /// 生成随机IV
        /// </summary>
        /// <param name="ivSize">IV长度（位）</param>
        /// <returns>随机IV</returns>
        public static byte[] GenerateRandomIV(int ivSize)
        {
            return StringUtil.GenerateRandomIV(ivSize);
        }

        /// <summary>
        /// 字节数组转十六进制字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>十六进制字符串</returns>
        public static string BytesToHex(byte[] bytes, bool upperCase = false)
        {
            return StringUtil.BytesToHex(bytes, upperCase);
        }

        /// <summary>
        /// 十六进制字符串转字节数组
        /// </summary>
        /// <param name="hex">十六进制字符串</param>
        /// <returns>字节数组</returns>
        public static byte[] HexToBytes(string hex)
        {
            return StringUtil.HexToBytes(hex);
        }

        /// <summary>
        /// 字节数组转Base64字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <returns>Base64字符串</returns>
        public static string BytesToBase64(byte[] bytes)
        {
            return StringUtil.BytesToBase64(bytes);
        }

        /// <summary>
        /// Base64字符串转字节数组
        /// </summary>
        /// <param name="base64">Base64字符串</param>
        /// <returns>字节数组</returns>
        public static byte[] Base64ToBytes(string base64)
        {
            return StringUtil.Base64ToBytes(base64);
        }

        /// <summary>
        /// 字符串转字节数组（UTF-8编码）
        /// </summary>
        /// <param name="text">字符串</param>
        /// <returns>字节数组</returns>
        public static byte[] StringToBytes(string text)
        {
            return StringUtil.StringToBytes(text);
        }

        /// <summary>
        /// 字节数组转字符串（UTF-8编码）
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <returns>字符串</returns>
        public static string BytesToString(byte[] bytes)
        {
            return StringUtil.BytesToString(bytes);
        }

        #endregion

        #region 异步方法

        /// <summary>
        /// 异步AES加密
        /// </summary>
        public static async Task<byte[]> AesEncryptAsync(byte[] data, byte[] key, byte[]? iv = null)
        {
            var aes = CryptoFactory.CreateAes();
            return await aes.EncryptAsync(data, key, iv);
        }

        /// <summary>
        /// 异步AES解密
        /// </summary>
        public static async Task<byte[]> AesDecryptAsync(byte[] encryptedData, byte[] key, byte[]? iv = null)
        {
            var aes = CryptoFactory.CreateAes();
            return await aes.DecryptAsync(encryptedData, key, iv);
        }

        /// <summary>
        /// 异步RSA加密
        /// </summary>
        public static async Task<byte[]> RsaEncryptAsync(byte[] data, byte[] publicKey)
        {
            var rsa = CryptoFactory.CreateRsa();
            return await rsa.EncryptAsync(data, publicKey);
        }

        /// <summary>
        /// 异步RSA解密
        /// </summary>
        public static async Task<byte[]> RsaDecryptAsync(byte[] encryptedData, byte[] privateKey)
        {
            var rsa = CryptoFactory.CreateRsa();
            return await rsa.DecryptAsync(encryptedData, privateKey);
        }

        /// <summary>
        /// 异步MD5哈希
        /// </summary>
        public static async Task<byte[]> Md5HashAsync(byte[] data)
        {
            var md5 = CryptoFactory.CreateMd5();
            return await md5.ComputeHashAsync(data);
        }

        /// <summary>
        /// 异步SM3哈希
        /// </summary>
        public static async Task<byte[]> Sm3HashAsync(byte[] data)
        {
            var sm3 = CryptoFactory.CreateSm3();
            return await sm3.ComputeHashAsync(data);
        }

        /// <summary>
        /// 异步SM2密文格式转换：C1C2C3转C1C3C2
        /// </summary>
        public static async Task<byte[]> Sm2ConvertC1C2C3ToC1C3C2Async(byte[] c1c2c3Data)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return await sm2.C1C2C3ToC1C3C2Async(c1c2c3Data);
        }

        /// <summary>
        /// 异步SM2密文格式转换：C1C3C2转C1C2C3
        /// </summary>
        public static async Task<byte[]> Sm2ConvertC1C3C2ToC1C2C3Async(byte[] c1c3c2Data)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return await sm2.C1C3C2ToC1C2C3Async(c1c3c2Data);
        }

        /// <summary>
        /// 异步SM2检测密文格式
        /// </summary>
        public static async Task<Algorithms.SM2.SM2CipherFormat> Sm2DetectCipherFormatAsync(byte[] cipherData)
        {
            var sm2 = CryptoFactory.CreateSm2();
            return await sm2.DetectCipherFormatAsync(cipherData);
        }

        #endregion
    }
}
