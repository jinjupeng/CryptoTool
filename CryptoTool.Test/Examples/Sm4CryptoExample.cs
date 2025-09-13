using System;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Algorithm.Algorithms.SM4;
using CryptoTool.Algorithm.Utils;

namespace CryptoTool.Test.Examples
{
    /// <summary>
    /// SM4加密算法使用示例
    /// </summary>
    public class Sm4CryptoExample
    {
        /// <summary>
        /// 基本加密解密示例
        /// </summary>
        public static void BasicExample()
        {
            Console.WriteLine("=== SM4基本加密解密示例 ===");
            
            // 创建SM4加密器（默认CBC模式，PKCS7填充）
            var sm4 = new Sm4Crypto();
            
            // 原始数据
            string originalText = "这是SM4国密算法测试数据，包含中文和English混合内容！";
            byte[] originalData = CryptoUtil.StringToBytes(originalText);
            
            // 生成密钥和IV
            byte[] key = sm4.GenerateKey();
            byte[] iv = sm4.GenerateIV();
            
            Console.WriteLine($"原始数据: {originalText}");
            Console.WriteLine($"密钥: {CryptoUtil.BytesToHex(key)}");
            Console.WriteLine($"IV: {CryptoUtil.BytesToHex(iv)}");
            
            // 加密
            byte[] encryptedData = sm4.Encrypt(originalData, key, iv);
            Console.WriteLine($"加密后: {CryptoUtil.BytesToHex(encryptedData)}");
            Console.WriteLine($"加密后(Base64): {CryptoUtil.BytesToBase64(encryptedData)}");
            
            // 解密
            byte[] decryptedData = sm4.Decrypt(encryptedData, key, iv);
            string decryptedText = CryptoUtil.BytesToString(decryptedData);
            Console.WriteLine($"解密后: {decryptedText}");
            
            // 验证
            Console.WriteLine($"加密解密成功: {originalText == decryptedText}");
            Console.WriteLine();
        }

        /// <summary>
        /// 不同加密模式示例
        /// </summary>
        public static void ModeExample()
        {
            Console.WriteLine("=== SM4不同加密模式示例 ===");
            
            string[] modes = { "CBC", "ECB", "CFB", "OFB", "CTR" };
            string testData = "SM4模式测试数据";
            byte[] data = CryptoUtil.StringToBytes(testData);
            byte[] key = CryptoUtil.GenerateRandomKey(128);
            
            foreach (string mode in modes)
            {
                try
                {
                    var sm4 = new Sm4Crypto(mode);
                    byte[] iv = mode == "ECB" ? null : sm4.GenerateIV();
                    
                    byte[] encrypted = sm4.Encrypt(data, key, iv);
                    byte[] decrypted = sm4.Decrypt(encrypted, key, iv);
                    string result = CryptoUtil.BytesToString(decrypted);
                    
                    Console.WriteLine($"{mode}模式: {(testData == result ? "成功" : "失败")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{mode}模式: 失败 - {ex.Message}");
                }
            }
            Console.WriteLine();
        }

        /// <summary>
        /// 不同填充模式示例
        /// </summary>
        public static void PaddingExample()
        {
            Console.WriteLine("=== SM4不同填充模式示例 ===");
            
            string[] paddings = { "PKCS7", "NoPadding", "ZeroPadding" };
            string testData = "填充模式测试";
            byte[] data = CryptoUtil.StringToBytes(testData);
            byte[] key = CryptoUtil.GenerateRandomKey(128);
            byte[] iv = CryptoUtil.GenerateRandomIV(128);
            
            foreach (string padding in paddings)
            {
                try
                {
                    var sm4 = new Sm4Crypto("CBC", padding);
                    
                    byte[] encrypted = sm4.Encrypt(data, key, iv);
                    byte[] decrypted = sm4.Decrypt(encrypted, key, iv);
                    string result = CryptoUtil.BytesToString(decrypted);
                    
                    Console.WriteLine($"{padding}填充: {(testData == result ? "成功" : "失败")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{padding}填充: 失败 - {ex.Message}");
                }
            }
            Console.WriteLine();
        }

        /// <summary>
        /// 密码派生密钥示例
        /// </summary>
        public static void PasswordDerivationExample()
        {
            Console.WriteLine("=== SM4密码派生密钥示例 ===");
            
            var sm4 = new Sm4Crypto();
            string password = "我的密码123";
            string testData = "使用密码派生的密钥进行加密";
            byte[] data = CryptoUtil.StringToBytes(testData);
            
            // 从密码派生密钥
            var (key, salt) = sm4.DeriveKeyFromPassword(password, 10000);
            
            Console.WriteLine($"密码: {password}");
            Console.WriteLine($"盐值: {CryptoUtil.BytesToHex(salt)}");
            Console.WriteLine($"派生密钥: {CryptoUtil.BytesToHex(key)}");
            
            // 加密
            byte[] encrypted = sm4.Encrypt(data, key);
            Console.WriteLine($"加密成功，数据长度: {encrypted.Length}");
            
            // 解密
            byte[] decrypted = sm4.Decrypt(encrypted, key);
            string result = CryptoUtil.BytesToString(decrypted);
            Console.WriteLine($"解密结果: {result}");
            Console.WriteLine($"加密解密成功: {testData == result}");
            Console.WriteLine();
        }

        /// <summary>
        /// 大文件加密示例
        /// </summary>
        public static void LargeDataExample()
        {
            Console.WriteLine("=== SM4大文件加密示例 ===");
            
            var sm4 = new Sm4Crypto();
            
            // 生成1MB的测试数据
            byte[] largeData = new byte[1024 * 1024];
            new Random().NextBytes(largeData);
            
            byte[] key = sm4.GenerateKey();
            byte[] iv = sm4.GenerateIV();
            
            Console.WriteLine($"原始数据大小: {largeData.Length} 字节");
            
            var startTime = DateTime.Now;
            
            // 加密
            byte[] encrypted = sm4.Encrypt(largeData, key, iv);
            var encryptTime = DateTime.Now - startTime;
            
            Console.WriteLine($"加密后大小: {encrypted.Length} 字节");
            Console.WriteLine($"加密耗时: {encryptTime.TotalMilliseconds} 毫秒");
            
            startTime = DateTime.Now;
            
            // 解密
            byte[] decrypted = sm4.Decrypt(encrypted, key, iv);
            var decryptTime = DateTime.Now - startTime;
            
            Console.WriteLine($"解密耗时: {decryptTime.TotalMilliseconds} 毫秒");
            Console.WriteLine($"数据完整性: {CryptoUtil.ByteArraysEqual(largeData, decrypted)}");
            Console.WriteLine();
        }

        /// <summary>
        /// 异步加密示例
        /// </summary>
        public static async Task AsyncExample()
        {
            Console.WriteLine("=== SM4异步加密示例 ===");
            
            var sm4 = new Sm4Crypto();
            string testData = "异步加密测试数据";
            byte[] data = CryptoUtil.StringToBytes(testData);
            byte[] key = sm4.GenerateKey();
            byte[] iv = sm4.GenerateIV();
            
            Console.WriteLine($"原始数据: {testData}");
            
            // 异步加密
            byte[] encrypted = await sm4.EncryptAsync(data, key, iv);
            Console.WriteLine($"异步加密完成，数据长度: {encrypted.Length}");
            
            // 异步解密
            byte[] decrypted = await sm4.DecryptAsync(encrypted, key, iv);
            string result = CryptoUtil.BytesToString(decrypted);
            Console.WriteLine($"异步解密结果: {result}");
            Console.WriteLine($"异步加密解密成功: {testData == result}");
            Console.WriteLine();
        }

        /// <summary>
        /// 运行所有示例
        /// </summary>
        public static async Task RunAllExamples()
        {
            Console.WriteLine("开始运行SM4加密算法示例...\n");
            
            try
            {
                BasicExample();
                ModeExample();
                PaddingExample();
                PasswordDerivationExample();
                LargeDataExample();
                await AsyncExample();
                
                Console.WriteLine("所有示例运行完成！");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"示例运行出错: {ex.Message}");
                Console.WriteLine($"详细错误: {ex}");
            }
        }
    }
}
