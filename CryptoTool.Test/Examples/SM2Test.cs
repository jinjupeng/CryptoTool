using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Algorithm.Enums;
using CryptoTool.Algorithm.Factory;
using CryptoTool.Algorithm.Interfaces;

namespace CryptoTool.Test.Examples
{
    internal class SM2Test
    {
        /// <summary>
        /// 运行SM2算法测试
        /// </summary>
        public static async Task RunTest()
        {
            Console.WriteLine("=== SM2算法测试 ===");
            
            try
            {
                // 创建SM2算法实例
                var sm2 = CryptoFactory.CreateSm2();
                Console.WriteLine($"算法名称: {sm2.AlgorithmName}");
                Console.WriteLine($"算法类型: {sm2.AlgorithmType}");
                
                // 测试数据
                string testData = "这是一个SM2加密测试数据，包含中文字符和特殊符号!@#$%^&*()";
                byte[] data = Encoding.UTF8.GetBytes(testData);
                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"数据长度: {data.Length} 字节");
                
                // 生成密钥对
                Console.WriteLine("\n--- 密钥对生成 ---");
                var (publicKey, privateKey) = sm2.GenerateKeyPair();
                Console.WriteLine($"公钥长度: {publicKey.Length} 字节");
                Console.WriteLine($"私钥长度: {privateKey.Length} 字节");
                Console.WriteLine($"公钥(Hex): {BitConverter.ToString(publicKey).Replace("-", "")}");
                
                // 加密测试
                Console.WriteLine("\n--- 加密测试 ---");
                byte[] encryptedData = sm2.Encrypt(data, publicKey);
                Console.WriteLine($"加密成功，加密数据长度: {encryptedData.Length} 字节");
                Console.WriteLine($"加密数据(Hex): {BitConverter.ToString(encryptedData).Replace("-", "")}");
                
                // 解密测试
                Console.WriteLine("\n--- 解密测试 ---");
                byte[] decryptedData = sm2.Decrypt(encryptedData, privateKey);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);
                Console.WriteLine($"解密成功，解密数据: {decryptedText}");
                
                // 验证结果
                bool isSuccess = testData == decryptedText;
                Console.WriteLine($"\n--- 测试结果 ---");
                Console.WriteLine($"测试结果: {(isSuccess ? "通过" : "失败")}");
                
                // 签名测试
                Console.WriteLine("\n--- 数字签名测试 ---");
                byte[] signature = sm2.Sign(data, privateKey);
                Console.WriteLine($"签名成功，签名长度: {signature.Length} 字节");
                Console.WriteLine($"签名(Hex): {BitConverter.ToString(signature).Replace("-", "")}");
                
                // 验证签名测试
                Console.WriteLine("\n--- 签名验证测试 ---");
                bool verifyResult = sm2.VerifySign(data, signature, publicKey);
                Console.WriteLine($"签名验证结果: {(verifyResult ? "通过" : "失败")}");
                
                // 异步测试
                Console.WriteLine("\n--- 异步加密解密测试 ---");
                byte[] asyncEncryptedData = await sm2.EncryptAsync(data, publicKey);
                byte[] asyncDecryptedData = await sm2.DecryptAsync(asyncEncryptedData, privateKey);
                string asyncDecryptedText = Encoding.UTF8.GetString(asyncDecryptedData);
                bool asyncSuccess = testData == asyncDecryptedText;
                Console.WriteLine($"异步加密解密测试结果: {(asyncSuccess ? "通过" : "失败")}");
                
                // 异步签名测试
                Console.WriteLine("\n--- 异步签名验证测试 ---");
                byte[] asyncSignature = await sm2.SignAsync(data, privateKey);
                bool asyncVerifyResult = await sm2.VerifySignAsync(data, asyncSignature, publicKey);
                Console.WriteLine($"异步签名验证测试结果: {(asyncVerifyResult ? "通过" : "失败")}");
                
                // 大数据测试
                Console.WriteLine("\n--- 大数据测试 ---");
                TestLargeData();
                
                // 多次加密测试
                Console.WriteLine("\n--- 多次加密测试 ---");
                TestMultipleEncryption();

                await TestSM2SignatureAlgorithm();


            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM2测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }
            
            Console.WriteLine("=== SM2算法测试完成 ===\n");
        }


        /// <summary>
        /// 测试SM2签名算法
        /// </summary>
        public static async Task TestSM2SignatureAlgorithm()
        {
            Console.WriteLine("=== SM2签名算法测试 ===");

            var _sm2Crypto = CryptoFactory.CreateSm2();
            var testData = Encoding.UTF8.GetBytes("Hello, 世界! 这是一个SM2签名算法测试。");
            var (publicKey, privateKey) = _sm2Crypto.GenerateKeyPair();

            // 测试SM3withSM2签名
            Console.WriteLine("\n--- SM3withSM2 签名测试 ---");
            await TestSM2WithSignature(testData, publicKey, privateKey, SignatureAlgorithm.SM3withSM2);

            Console.WriteLine("SM2签名算法测试完成！\n");
        }

        /// <summary>
        /// 测试大数据
        /// </summary>
        private static void TestLargeData()
        {
            var sm2 = CryptoFactory.CreateSm2();
            var (publicKey, privateKey) = sm2.GenerateKeyPair();
            
            // 生成较大的测试数据
            string largeData = new string('A', 1000);
            byte[] data = Encoding.UTF8.GetBytes(largeData);
            
            try
            {
                byte[] encryptedData = sm2.Encrypt(data, publicKey);
                byte[] decryptedData = sm2.Decrypt(encryptedData, privateKey);
                bool success = data.SequenceEqual(decryptedData);
                Console.WriteLine($"大数据测试(1000字节): {(success ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"大数据测试失败: {ex.Message}");
            }
        }
        
        /// <summary>
        /// 测试多次加密
        /// </summary>
        private static void TestMultipleEncryption()
        {
            var sm2 = CryptoFactory.CreateSm2();
            var (publicKey, privateKey) = sm2.GenerateKeyPair();
            
            string testData = "SM2多次加密测试数据";
            byte[] data = Encoding.UTF8.GetBytes(testData);
            
            try
            {
                // 连续加密解密5次
                byte[] currentData = data;
                for (int i = 0; i < 5; i++)
                {
                    byte[] encryptedData = sm2.Encrypt(currentData, publicKey);
                    byte[] decryptedData = sm2.Decrypt(encryptedData, privateKey);
                    currentData = decryptedData;
                }
                
                bool success = data.SequenceEqual(currentData);
                Console.WriteLine($"多次加密测试(5次): {(success ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"多次加密测试失败: {ex.Message}");
            }
        }


        /// <summary>
        /// 测试SM2指定签名算法
        /// </summary>
        private static async Task TestSM2WithSignature(byte[] data, byte[] publicKey, byte[] privateKey, SignatureAlgorithm signatureAlgorithm)
        {
            var _sm2Crypto = CryptoFactory.CreateSm2();
            try
            {
                // 签名
                var signature = await _sm2Crypto.SignAsync(data, privateKey, signatureAlgorithm);
                Console.WriteLine($"✓ 签名成功 (算法: {signatureAlgorithm})");
                Console.WriteLine($"  签名长度: {signature.Length} 字节");

                // 验证签名
                var isValid = await _sm2Crypto.VerifySignAsync(data, signature, publicKey, signatureAlgorithm);

                if (isValid)
                {
                    Console.WriteLine($"✓ 签名验证成功");
                }
                else
                {
                    Console.WriteLine($"✗ 签名验证失败");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ 测试失败: {ex.Message}");
            }
        }

    }
}
