using CryptoTool.Algorithm.Algorithms.RSA;
using CryptoTool.Algorithm.Enums;
using CryptoTool.Algorithm.Factory;
using CryptoTool.Algorithm.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Test.Examples
{
    internal class RSATest
    {
        /// <summary>
        /// 运行RSA算法测试
        /// </summary>
        public static async Task RunTest()
        {
            Console.WriteLine("=== RSA算法测试 ===");
            
            try
            {
                // 创建RSA算法实例
                var rsa = CryptoFactory.CreateRsa(2048);
                Console.WriteLine($"算法名称: {rsa.AlgorithmName}");
                Console.WriteLine($"算法类型: {rsa.AlgorithmType}");
                
                // 测试数据
                string testData = "这是一个RSA加密测试数据，包含中文字符和特殊符号!@#$%^&*()";
                byte[] data = Encoding.UTF8.GetBytes(testData);
                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"数据长度: {data.Length} 字节");
                
                // 生成密钥对
                Console.WriteLine("\n--- 密钥对生成 ---");
                var (publicKey, privateKey) = rsa.GenerateKeyPair();
                Console.WriteLine($"公钥长度: {publicKey.Length} 字节");
                Console.WriteLine($"私钥长度: {privateKey.Length} 字节");
                Console.WriteLine($"公钥(Hex): {BitConverter.ToString(publicKey).Replace("-", "")}");
                
                // 加密测试
                Console.WriteLine("\n--- 加密测试 ---");
                byte[] encryptedData = rsa.Encrypt(data, publicKey);
                Console.WriteLine($"加密成功，加密数据长度: {encryptedData.Length} 字节");
                Console.WriteLine($"加密数据(Hex): {BitConverter.ToString(encryptedData).Replace("-", "")}");
                
                // 解密测试
                Console.WriteLine("\n--- 解密测试 ---");
                byte[] decryptedData = rsa.Decrypt(encryptedData, privateKey);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);
                Console.WriteLine($"解密成功，解密数据: {decryptedText}");
                
                // 验证结果
                bool isSuccess = testData == decryptedText;
                Console.WriteLine($"\n--- 测试结果 ---");
                Console.WriteLine($"测试结果: {(isSuccess ? "通过" : "失败")}");
                
                // 签名测试
                Console.WriteLine("\n--- 数字签名测试 ---");
                byte[] signature = rsa.Sign(data, privateKey);
                Console.WriteLine($"签名成功，签名长度: {signature.Length} 字节");
                Console.WriteLine($"签名(Hex): {BitConverter.ToString(signature).Replace("-", "")}");
                
                // 验证签名测试
                Console.WriteLine("\n--- 签名验证测试 ---");
                bool verifyResult = rsa.VerifySign(data, signature, publicKey);
                Console.WriteLine($"签名验证结果: {(verifyResult ? "通过" : "失败")}");
                
                // 异步测试
                Console.WriteLine("\n--- 异步加密解密测试 ---");
                byte[] asyncEncryptedData = await rsa.EncryptAsync(data, publicKey);
                byte[] asyncDecryptedData = await rsa.DecryptAsync(asyncEncryptedData, privateKey);
                string asyncDecryptedText = Encoding.UTF8.GetString(asyncDecryptedData);
                bool asyncSuccess = testData == asyncDecryptedText;
                Console.WriteLine($"异步加密解密测试结果: {(asyncSuccess ? "通过" : "失败")}");
                
                // 异步签名测试
                Console.WriteLine("\n--- 异步签名验证测试 ---");
                byte[] asyncSignature = await rsa.SignAsync(data, privateKey);
                bool asyncVerifyResult = await rsa.VerifySignAsync(data, asyncSignature, publicKey);
                Console.WriteLine($"异步签名验证测试结果: {(asyncVerifyResult ? "通过" : "失败")}");
                
                // 不同密钥长度测试
                Console.WriteLine("\n--- 不同密钥长度测试 ---");
                TestDifferentKeySizes();
                
                // 大数据测试
                Console.WriteLine("\n--- 大数据测试 ---");
                TestLargeData();

                await TestRSAPaddingModes();

                await TestRSASignatureAlgorithms();


            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }
            
            Console.WriteLine("=== RSA算法测试完成 ===\n");
        }


        /// <summary>
        /// 测试RSA多种填充模式
        /// </summary>
        public static async Task TestRSAPaddingModes()
        {
            var _rsaCrypto = new RsaCrypto(2048);
            Console.WriteLine("=== RSA多种填充模式测试 ===");

            var testData = Encoding.UTF8.GetBytes("Hello, 世界! 这是一个RSA填充模式测试。");
            var (publicKey, privateKey) = _rsaCrypto.GenerateKeyPair();

            // 测试PKCS1填充
            Console.WriteLine("\n--- PKCS1填充测试 ---");
            await TestRSAWithPadding(testData, publicKey, privateKey, AsymmetricPaddingMode.PKCS1);

            // 测试OAEP填充
            Console.WriteLine("\n--- OAEP填充测试 ---");
            await TestRSAWithPadding(testData, publicKey, privateKey, AsymmetricPaddingMode.OAEP);

            Console.WriteLine("RSA填充模式测试完成！\n");
        }

        /// <summary>
        /// 测试RSA多种签名算法
        /// </summary>
        public static async Task TestRSASignatureAlgorithms()
        {
            var _rsaCrypto = new RsaCrypto(2048);
            Console.WriteLine("=== RSA多种签名算法测试 ===");

            var testData = Encoding.UTF8.GetBytes("Hello, 世界! 这是一个RSA签名算法测试。");
            var (publicKey, privateKey) = _rsaCrypto.GenerateKeyPair();

            // 测试各种签名算法
            var algorithms = new[]
            {
                SignatureAlgorithm.SHA256withRSA,
                SignatureAlgorithm.SHA384withRSA,
                SignatureAlgorithm.SHA512withRSA,
                SignatureAlgorithm.SHA256withRSA_PSS,
                SignatureAlgorithm.SHA384withRSA_PSS,
                SignatureAlgorithm.SHA512withRSA_PSS
            };

            foreach (var algorithm in algorithms)
            {
                Console.WriteLine($"\n--- {algorithm} 签名测试 ---");
                await TestRSAWithSignature(testData, publicKey, privateKey, algorithm);
            }

            Console.WriteLine("RSA签名算法测试完成！\n");
        }

        /// <summary>
        /// 测试不同的密钥长度
        /// </summary>
        private static void TestDifferentKeySizes()
        {
            int[] keySizes = { 1024, 2048, 4096 };
            string testData = "RSA不同密钥长度测试数据";
            byte[] data = Encoding.UTF8.GetBytes(testData);
            
            foreach (int keySize in keySizes)
            {
                try
                {
                    var rsa = CryptoFactory.CreateRsa(keySize);
                    var (publicKey, privateKey) = rsa.GenerateKeyPair();
                    
                    byte[] encryptedData = rsa.Encrypt(data, publicKey);
                    byte[] decryptedData = rsa.Decrypt(encryptedData, privateKey);
                    bool success = data.SequenceEqual(decryptedData);
                    
                    Console.WriteLine($"RSA-{keySize}测试: {(success ? "通过" : "失败")}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"RSA-{keySize}测试失败: {ex.Message}");
                }
            }
        }
        
        /// <summary>
        /// 测试大数据
        /// </summary>
        private static void TestLargeData()
        {
            var rsa = CryptoFactory.CreateRsa(2048);
            var (publicKey, privateKey) = rsa.GenerateKeyPair();
            
            // 生成较大的测试数据（RSA有数据长度限制）
            string largeData = new string('A', 100); // RSA-2048最多可以加密245字节
            byte[] data = Encoding.UTF8.GetBytes(largeData);
            
            try
            {
                byte[] encryptedData = rsa.Encrypt(data, publicKey);
                byte[] decryptedData = rsa.Decrypt(encryptedData, privateKey);
                bool success = data.SequenceEqual(decryptedData);
                Console.WriteLine($"大数据测试(100字节): {(success ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"大数据测试失败: {ex.Message}");
            }
        }


        /// <summary>
        /// 测试RSA指定填充模式
        /// </summary>
        private static async Task TestRSAWithPadding(byte[] data, byte[] publicKey, byte[] privateKey, AsymmetricPaddingMode paddingMode)
        {
            var _rsaCrypto = new RsaCrypto(2048);
            try
            {
                // 加密
                var encrypted = await _rsaCrypto.EncryptAsync(data, publicKey, paddingMode);
                Console.WriteLine($"✓ 加密成功 (填充模式: {paddingMode})");
                Console.WriteLine($"  密文长度: {encrypted.Length} 字节");

                // 解密
                var decrypted = await _rsaCrypto.DecryptAsync(encrypted, privateKey, paddingMode);
                var decryptedText = Encoding.UTF8.GetString(decrypted);

                if (decryptedText == Encoding.UTF8.GetString(data))
                {
                    Console.WriteLine($"✓ 解密成功，数据一致");
                }
                else
                {
                    Console.WriteLine($"✗ 解密失败，数据不一致");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ 测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试RSA指定签名算法
        /// </summary>
        private static async Task TestRSAWithSignature(byte[] data, byte[] publicKey, byte[] privateKey, SignatureAlgorithm signatureAlgorithm)
        {
            var _rsaCrypto = new RsaCrypto(2048);
            try
            {
                // 签名
                var signature = await _rsaCrypto.SignAsync(data, privateKey, signatureAlgorithm);
                Console.WriteLine($"✓ 签名成功 (算法: {signatureAlgorithm})");
                Console.WriteLine($"  签名长度: {signature.Length} 字节");

                // 验证签名
                var isValid = await _rsaCrypto.VerifySignAsync(data, signature, publicKey, signatureAlgorithm);

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
