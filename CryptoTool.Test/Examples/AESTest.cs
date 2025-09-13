using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Algorithm.Factory;
using CryptoTool.Algorithm.Interfaces;

namespace CryptoTool.Test.Examples
{
    internal class AESTest
    {
        /// <summary>
        /// 运行AES算法测试
        /// </summary>
        public static async Task RunTest()
        {
            Console.WriteLine("=== AES算法测试 ===");
            
            try
            {
                // 创建AES算法实例
                var aes = CryptoFactory.CreateAes(256);
                Console.WriteLine($"算法名称: {aes.AlgorithmName}");
                Console.WriteLine($"算法类型: {aes.AlgorithmType}");
                
                // 测试数据
                string testData = "这是一个AES加密测试数据，包含中文字符和特殊符号!@#$%^&*()";
                byte[] data = Encoding.UTF8.GetBytes(testData);
                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"数据长度: {data.Length} 字节");
                
                // 生成密钥和IV
                byte[] key = aes.GenerateKey();
                byte[] iv = aes.GenerateIV();
                Console.WriteLine($"密钥长度: {key.Length} 字节");
                Console.WriteLine($"IV长度: {iv.Length} 字节");
                
                // 加密测试
                Console.WriteLine("\n--- 加密测试 ---");
                byte[] encryptedData = aes.Encrypt(data, key, iv);
                Console.WriteLine($"加密成功，加密数据长度: {encryptedData.Length} 字节");
                Console.WriteLine($"加密数据(Hex): {BitConverter.ToString(encryptedData).Replace("-", "")}");
                
                // 解密测试
                Console.WriteLine("\n--- 解密测试 ---");
                byte[] decryptedData = aes.Decrypt(encryptedData, key, iv);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);
                Console.WriteLine($"解密成功，解密数据: {decryptedText}");
                
                // 验证结果
                bool isSuccess = testData == decryptedText;
                Console.WriteLine($"\n--- 测试结果 ---");
                Console.WriteLine($"测试结果: {(isSuccess ? "通过" : "失败")}");
                
                // 异步测试
                Console.WriteLine("\n--- 异步加密解密测试 ---");
                byte[] asyncEncryptedData = await aes.EncryptAsync(data, key, iv);
                byte[] asyncDecryptedData = await aes.DecryptAsync(asyncEncryptedData, key, iv);
                string asyncDecryptedText = Encoding.UTF8.GetString(asyncDecryptedData);
                bool asyncSuccess = testData == asyncDecryptedText;
                Console.WriteLine($"异步测试结果: {(asyncSuccess ? "通过" : "失败")}");
                
                // 不同模式测试
                Console.WriteLine("\n--- 不同加密模式测试 ---");
                TestDifferentModes();
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"AES测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }
            
            Console.WriteLine("=== AES算法测试完成 ===\n");
        }
        
        /// <summary>
        /// 测试不同的加密模式
        /// </summary>
        private static void TestDifferentModes()
        {
            string testData = "AES不同模式测试数据";
            byte[] data = Encoding.UTF8.GetBytes(testData);
            
            // 测试CBC模式
            var aesCbc = CryptoFactory.CreateAes(256, System.Security.Cryptography.CipherMode.CBC);
            byte[] key = aesCbc.GenerateKey();
            byte[] iv = aesCbc.GenerateIV();
            byte[] encryptedCbc = aesCbc.Encrypt(data, key, iv);
            byte[] decryptedCbc = aesCbc.Decrypt(encryptedCbc, key, iv);
            bool cbcSuccess = data.SequenceEqual(decryptedCbc);
            Console.WriteLine($"CBC模式测试: {(cbcSuccess ? "通过" : "失败")}");
            
            // 测试ECB模式
            var aesEcb = CryptoFactory.CreateAes(256, System.Security.Cryptography.CipherMode.ECB);
            byte[] keyEcb = aesEcb.GenerateKey();
            byte[] encryptedEcb = aesEcb.Encrypt(data, keyEcb);
            byte[] decryptedEcb = aesEcb.Decrypt(encryptedEcb, keyEcb);
            bool ecbSuccess = data.SequenceEqual(decryptedEcb);
            Console.WriteLine($"ECB模式测试: {(ecbSuccess ? "通过" : "失败")}");
        }
    }
}
