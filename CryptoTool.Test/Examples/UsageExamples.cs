using System;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Algorithm;
using CryptoTool.Algorithm.Factory;
using CryptoTool.Algorithm.Utils;

namespace CryptoTool.Test.Examples
{
    /// <summary>
    /// 使用示例
    /// </summary>
    public static class UsageExamples
    {
        /// <summary>
        /// 基本使用示例
        /// </summary>
        public static void BasicUsageExample()
        {
            Console.WriteLine("=== 基本使用示例 ===");

            // 1. 字符串转字节数组
            string originalText = "Hello, 加密算法类库!";
            byte[] data = Algorithm.CryptoTool.StringToBytes(originalText);
            Console.WriteLine($"原始文本: {originalText}");

            // 2. AES加密解密
            byte[] aesKey = Algorithm.CryptoTool.GenerateRandomKey(256);
            byte[] aesEncrypted = Algorithm.CryptoTool.AesEncrypt(data, aesKey);
            byte[] aesDecrypted = Algorithm.CryptoTool.AesDecrypt(aesEncrypted, aesKey);
            string aesResult = Algorithm.CryptoTool.BytesToString(aesDecrypted);
            Console.WriteLine($"AES解密结果: {aesResult}");

            // 3. MD5哈希
            byte[] md5Hash = Algorithm.CryptoTool.Md5Hash(data);
            string md5Hex = Algorithm.CryptoTool.BytesToHex(md5Hash, true);
            Console.WriteLine($"MD5哈希值: {md5Hex}");

            // 4. SM3哈希
            byte[] sm3Hash = Algorithm.CryptoTool.Sm3Hash(data);
            string sm3Hex = Algorithm.CryptoTool.BytesToHex(sm3Hash, true);
            Console.WriteLine($"SM3哈希值: {sm3Hex}");
        }

        /// <summary>
        /// RSA加密解密示例
        /// </summary>
        public static void RsaExample()
        {
            Console.WriteLine("\n=== RSA加密解密示例 ===");

            string text = "RSA加密测试数据";
            byte[] data = Algorithm.CryptoTool.StringToBytes(text);

            // 生成RSA密钥对
            var (publicKey, privateKey) = Algorithm.CryptoTool.RsaGenerateKeyPair(2048);
            Console.WriteLine($"公钥长度: {publicKey.Length} 字节");
            Console.WriteLine($"私钥长度: {privateKey.Length} 字节");

            // 加密
            byte[] encrypted = Algorithm.CryptoTool.RsaEncrypt(data, publicKey);
            Console.WriteLine($"加密后长度: {encrypted.Length} 字节");

            // 解密
            byte[] decrypted = Algorithm.CryptoTool.RsaDecrypt(encrypted, privateKey);
            string result = Algorithm.CryptoTool.BytesToString(decrypted);
            Console.WriteLine($"解密结果: {result}");

            // 签名和验证
            byte[] signature = Algorithm.CryptoTool.RsaSign(data, privateKey);
            bool isValid = Algorithm.CryptoTool.RsaVerifySignature(data, signature, publicKey);
            Console.WriteLine($"签名验证结果: {isValid}");
        }

        /// <summary>
        /// SM2国密算法示例
        /// </summary>
        public static void Sm2Example()
        {
            Console.WriteLine("\n=== SM2国密算法示例 ===");

            string text = "SM2国密算法测试";
            byte[] data = Algorithm.CryptoTool.StringToBytes(text);

            // 生成SM2密钥对
            var (publicKey, privateKey) = Algorithm.CryptoTool.Sm2GenerateKeyPair();
            Console.WriteLine($"SM2公钥长度: {publicKey.Length} 字节");
            Console.WriteLine($"SM2私钥长度: {privateKey.Length} 字节");

            // 加密
            byte[] encrypted = Algorithm.CryptoTool.Sm2Encrypt(data, publicKey);
            Console.WriteLine($"SM2加密后长度: {encrypted.Length} 字节");

            // 解密
            byte[] decrypted = Algorithm.CryptoTool.Sm2Decrypt(encrypted, privateKey);
            string result = Algorithm.CryptoTool.BytesToString(decrypted);
            Console.WriteLine($"SM2解密结果: {result}");

            // 签名和验证
            byte[] signature = Algorithm.CryptoTool.Sm2Sign(data, privateKey);
            bool isValid = Algorithm.CryptoTool.Sm2VerifySignature(data, signature, publicKey);
            Console.WriteLine($"SM2签名验证结果: {isValid}");
        }

        /// <summary>
        /// 对称加密算法对比示例
        /// </summary>
        public static void SymmetricCryptoComparison()
        {
            Console.WriteLine("\n=== 对称加密算法对比示例 ===");

            string text = "对称加密算法对比测试数据";
            byte[] data = Algorithm.CryptoTool.StringToBytes(text);

            // AES加密
            byte[] aesKey = Algorithm.CryptoTool.GenerateRandomKey(256);
            byte[] aesEncrypted = Algorithm.CryptoTool.AesEncrypt(data, aesKey);
            byte[] aesDecrypted = Algorithm.CryptoTool.AesDecrypt(aesEncrypted, aesKey);
            Console.WriteLine($"AES加密解密成功: {Algorithm.CryptoTool.BytesToString(aesDecrypted) == text}");

            // DES加密
            byte[] desKey = Algorithm.CryptoTool.GenerateRandomKey(64);
            byte[] desEncrypted = Algorithm.CryptoTool.DesEncrypt(data, desKey);
            byte[] desDecrypted = Algorithm.CryptoTool.DesDecrypt(desEncrypted, desKey);
            Console.WriteLine($"DES加密解密成功: {Algorithm.CryptoTool.BytesToString(desDecrypted) == text}");

            // SM4加密
            byte[] sm4Key = Algorithm.CryptoTool.GenerateRandomKey(128);
            byte[] sm4Encrypted = Algorithm.CryptoTool.Sm4Encrypt(data, sm4Key);
            byte[] sm4Decrypted = Algorithm.CryptoTool.Sm4Decrypt(sm4Encrypted, sm4Key);
            Console.WriteLine($"SM4加密解密成功: {Algorithm.CryptoTool.BytesToString(sm4Decrypted) == text}");
        }

        /// <summary>
        /// 哈希算法对比示例
        /// </summary>
        public static void HashAlgorithmComparison()
        {
            Console.WriteLine("\n=== 哈希算法对比示例 ===");

            string text = "哈希算法对比测试数据";
            byte[] data = Algorithm.CryptoTool.StringToBytes(text);

            // MD5哈希
            string md5Hash = Algorithm.CryptoTool.Md5HashString(data, true);
            Console.WriteLine($"MD5哈希值: {md5Hash}");

            // SM3哈希
            string sm3Hash = Algorithm.CryptoTool.Sm3HashString(data, true);
            Console.WriteLine($"SM3哈希值: {sm3Hash}");

            // 验证哈希
            bool md5Valid = Algorithm.CryptoTool.Md5HashString(data, true) == md5Hash;
            bool sm3Valid = Algorithm.CryptoTool.Sm3HashString(data, true) == sm3Hash;
            Console.WriteLine($"MD5哈希验证: {md5Valid}");
            Console.WriteLine($"SM3哈希验证: {sm3Valid}");
        }

        /// <summary>
        /// 工厂模式使用示例
        /// </summary>
        public static void FactoryPatternExample()
        {
            Console.WriteLine("\n=== 工厂模式使用示例 ===");

            // 使用工厂创建算法实例
            var aes = CryptoFactory.CreateAes(256);
            var rsa = CryptoFactory.CreateRsa(2048);
            var md5 = CryptoFactory.CreateMd5();
            var sm2 = CryptoFactory.CreateSm2();
            var sm3 = CryptoFactory.CreateSm3();
            var sm4 = CryptoFactory.CreateSm4();

            Console.WriteLine($"支持的算法: {string.Join(", ", CryptoFactory.GetSupportedAlgorithms())}");
            Console.WriteLine($"AES算法类型: {aes.AlgorithmType}");
            Console.WriteLine($"RSA算法类型: {rsa.AlgorithmType}");
            Console.WriteLine($"MD5算法类型: {md5.AlgorithmType}");
            Console.WriteLine($"SM2算法类型: {sm2.AlgorithmType}");
            Console.WriteLine($"SM3算法类型: {sm3.AlgorithmType}");
            Console.WriteLine($"SM4算法类型: {sm4.AlgorithmType}");
        }

        /// <summary>
        /// 工具方法示例
        /// </summary>
        public static void UtilityMethodsExample()
        {
            Console.WriteLine("\n=== 工具方法示例 ===");

            // 字节数组和十六进制字符串转换
            byte[] data = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
            string hex = Algorithm.CryptoTool.BytesToHex(data, true);
            byte[] fromHex = Algorithm.CryptoTool.HexToBytes(hex);
            Console.WriteLine($"原始数据: {Algorithm.CryptoTool.BytesToString(data)}");
            Console.WriteLine($"十六进制: {hex}");
            Console.WriteLine($"转换回字节数组: {Algorithm.CryptoTool.BytesToString(fromHex)}");

            // Base64编码解码
            string base64 = Algorithm.CryptoTool.BytesToBase64(data);
            byte[] fromBase64 = Algorithm.CryptoTool.Base64ToBytes(base64);
            Console.WriteLine($"Base64编码: {base64}");
            Console.WriteLine($"Base64解码: {Algorithm.CryptoTool.BytesToString(fromBase64)}");

            // 随机数据生成
            byte[] randomKey = Algorithm.CryptoTool.GenerateRandomKey(256);
            byte[] randomIV = Algorithm.CryptoTool.GenerateRandomIV(128);
            Console.WriteLine($"随机密钥长度: {randomKey.Length} 字节");
            Console.WriteLine($"随机IV长度: {randomIV.Length} 字节");
        }

        /// <summary>
        /// SM2密文格式转换示例
        /// </summary>
        public static async Task Sm2CipherFormatExample()
        {
            Console.WriteLine("\n=== SM2密文格式转换示例 ===");

            // 创建模拟的C1C2C3格式密文
            var c1c2c3Data = CreateMockC1C2C3Data();
            Console.WriteLine($"原始C1C2C3密文长度: {c1c2c3Data.Length} 字节");

            // 转换为C1C3C2格式
            var c1c3c2Data = Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2(c1c2c3Data);
            Console.WriteLine($"转换后C1C3C2密文长度: {c1c3c2Data.Length} 字节");

            // 转换回C1C2C3格式
            var convertedBack = Algorithm.CryptoTool.Sm2ConvertC1C3C2ToC1C2C3(c1c3c2Data);
            Console.WriteLine($"转换回C1C2C3密文长度: {convertedBack.Length} 字节");

            // 检测密文格式
            var format1 = Algorithm.CryptoTool.Sm2DetectCipherFormat(c1c2c3Data);
            var format2 = Algorithm.CryptoTool.Sm2DetectCipherFormat(c1c3c2Data);
            Console.WriteLine($"C1C2C3格式检测: {format1}");
            Console.WriteLine($"C1C3C2格式检测: {format2}");

            // 验证转换结果
            bool isEqual = CryptoUtil.ByteArraysEqual(c1c2c3Data, convertedBack);
            Console.WriteLine($"格式转换验证: {(isEqual ? "成功" : "失败")}");

            // 异步转换示例
            var asyncConverted = await Algorithm.CryptoTool.Sm2ConvertC1C2C3ToC1C3C2Async(c1c2c3Data);
            Console.WriteLine($"异步转换结果长度: {asyncConverted.Length} 字节");
        }

        /// <summary>
        /// 运行所有示例
        /// </summary>
        public static async Task RunAllExamples()
        {
            try
            {
                BasicUsageExample();
                RsaExample();
                Sm2Example();
                SymmetricCryptoComparison();
                HashAlgorithmComparison();
                FactoryPatternExample();
                UtilityMethodsExample();
                await Sm2CipherFormatExample();
                
                // 运行SM2生产环境示例
                Console.WriteLine("\n=== 运行SM2生产环境示例 ===");
                Sm2ProductionExample.RunExample();
                Sm2ProductionExample.PerformanceTest();
                
                // 运行SM4生产环境示例
                Console.WriteLine("\n=== 运行SM4生产环境示例 ===");
                await Sm4CryptoExample.RunAllExamples();
                
                Console.WriteLine("\n=== 所有示例运行完成 ===");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"示例运行出错: {ex.Message}");
            }
        }

        /// <summary>
        /// 创建模拟的C1C2C3格式密文数据
        /// </summary>
        /// <param name="c2Length">C2组件长度</param>
        /// <returns>模拟密文数据</returns>
        private static byte[] CreateMockC1C2C3Data(int c2Length = 50)
        {
            var random = new Random();
            var data = new byte[65 + c2Length + 32]; // C1(65) + C2(可变) + C3(32)
            var offset = 0;

            // C1: 椭圆曲线点 (1字节标识 + 32字节X + 32字节Y)
            data[offset] = 0x04; // 未压缩点格式标识
            offset++;
            random.NextBytes(data, offset, 32); // X坐标
            offset += 32;
            random.NextBytes(data, offset, 32); // Y坐标
            offset += 32;

            // C2: 密文数据
            random.NextBytes(data, offset, c2Length);
            offset += c2Length;

            // C3: 哈希值
            random.NextBytes(data, offset, 32);

            return data;
        }
    }

}
