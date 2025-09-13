using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Algorithm.Factory;
using CryptoTool.Algorithm.Interfaces;

namespace CryptoTool.Test.Examples
{
    internal class DESTest
    {
        /// <summary>
        /// 运行DES算法测试
        /// </summary>
        public static async Task RunTest()
        {
            Console.WriteLine("=== DES算法测试 ===");
            
            try
            {
                // 创建DES算法实例
                var des = CryptoFactory.CreateDes();
                Console.WriteLine($"算法名称: {des.AlgorithmName}");
                Console.WriteLine($"算法类型: {des.AlgorithmType}");
                
                // 测试数据
                string testData = "这是一个DES加密测试数据，包含中文字符和特殊符号!@#$%^&*()";
                byte[] data = Encoding.UTF8.GetBytes(testData);
                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"数据长度: {data.Length} 字节");
                
                // 生成密钥和IV
                byte[] key = des.GenerateKey();
                byte[] iv = des.GenerateIV();
                Console.WriteLine($"密钥长度: {key.Length} 字节");
                Console.WriteLine($"IV长度: {iv.Length} 字节");
                
                // 加密测试
                Console.WriteLine("\n--- 加密测试 ---");
                byte[] encryptedData = des.Encrypt(data, key, iv);
                Console.WriteLine($"加密成功，加密数据长度: {encryptedData.Length} 字节");
                Console.WriteLine($"加密数据(Hex): {BitConverter.ToString(encryptedData).Replace("-", "")}");
                
                // 解密测试
                Console.WriteLine("\n--- 解密测试 ---");
                byte[] decryptedData = des.Decrypt(encryptedData, key, iv);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);
                Console.WriteLine($"解密成功，解密数据: {decryptedText}");
                
                // 验证结果
                bool isSuccess = testData == decryptedText;
                Console.WriteLine($"\n--- 测试结果 ---");
                Console.WriteLine($"测试结果: {(isSuccess ? "通过" : "失败")}");
                
                // 异步测试
                Console.WriteLine("\n--- 异步加密解密测试 ---");
                byte[] asyncEncryptedData = await des.EncryptAsync(data, key, iv);
                byte[] asyncDecryptedData = await des.DecryptAsync(asyncEncryptedData, key, iv);
                string asyncDecryptedText = Encoding.UTF8.GetString(asyncDecryptedData);
                bool asyncSuccess = testData == asyncDecryptedText;
                Console.WriteLine($"异步测试结果: {(asyncSuccess ? "通过" : "失败")}");
                
                // 不同模式测试
                Console.WriteLine("\n--- 不同加密模式测试 ---");
                TestDifferentModes();
                
                // 大数据测试
                Console.WriteLine("\n--- 大数据测试 ---");
                TestLargeData();
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DES测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }
            
            Console.WriteLine("=== DES算法测试完成 ===\n");
        }
        
        /// <summary>
        /// 测试不同的加密模式
        /// </summary>
        private static void TestDifferentModes()
        {
            string testData = "DES不同模式测试数据";
            byte[] data = Encoding.UTF8.GetBytes(testData);
            
            // 测试CBC模式
            var desCbc = CryptoFactory.CreateDes(System.Security.Cryptography.CipherMode.CBC);
            byte[] key = desCbc.GenerateKey();
            byte[] iv = desCbc.GenerateIV();
            byte[] encryptedCbc = desCbc.Encrypt(data, key, iv);
            byte[] decryptedCbc = desCbc.Decrypt(encryptedCbc, key, iv);
            bool cbcSuccess = data.SequenceEqual(decryptedCbc);
            Console.WriteLine($"CBC模式测试: {(cbcSuccess ? "通过" : "失败")}");
            
            // 测试ECB模式
            var desEcb = CryptoFactory.CreateDes(System.Security.Cryptography.CipherMode.ECB);
            byte[] keyEcb = desEcb.GenerateKey();
            byte[] encryptedEcb = desEcb.Encrypt(data, keyEcb);
            byte[] decryptedEcb = desEcb.Decrypt(encryptedEcb, keyEcb);
            bool ecbSuccess = data.SequenceEqual(decryptedEcb);
            Console.WriteLine($"ECB模式测试: {(ecbSuccess ? "通过" : "失败")}");
            
            // 测试CFB模式
            var desCfb = CryptoFactory.CreateDes(System.Security.Cryptography.CipherMode.CFB);
            byte[] keyCfb = desCfb.GenerateKey();
            byte[] ivCfb = desCfb.GenerateIV();
            byte[] encryptedCfb = desCfb.Encrypt(data, keyCfb, ivCfb);
            byte[] decryptedCfb = desCfb.Decrypt(encryptedCfb, keyCfb, ivCfb);
            bool cfbSuccess = data.SequenceEqual(decryptedCfb);
            Console.WriteLine($"CFB模式测试: {(cfbSuccess ? "通过" : "失败")}");
        }
        
        /// <summary>
        /// 测试大数据
        /// </summary>
        private static void TestLargeData()
        {
            var des = CryptoFactory.CreateDes();
            byte[] key = des.GenerateKey();
            byte[] iv = des.GenerateIV();
            
            // 生成1KB的测试数据
            string largeData = new string('A', 1024);
            byte[] data = Encoding.UTF8.GetBytes(largeData);
            
            try
            {
                byte[] encryptedData = des.Encrypt(data, key, iv);
                byte[] decryptedData = des.Decrypt(encryptedData, key, iv);
                bool success = data.SequenceEqual(decryptedData);
                Console.WriteLine($"大数据测试(1KB): {(success ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"大数据测试失败: {ex.Message}");
            }
        }
    }
}
