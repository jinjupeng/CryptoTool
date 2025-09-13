using System;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Algorithm.Algorithms.SM2;
using CryptoTool.Algorithm.Exceptions;

namespace CryptoTool.Test.Examples
{
    /// <summary>
    /// SM2生产环境实现示例
    /// </summary>
    public class Sm2ProductionExample
    {
        /// <summary>
        /// 运行SM2示例
        /// </summary>
        public static async Task RunExample()
        {
            Console.WriteLine("=== SM2生产环境实现示例 ===\n");

            try
            {
                var sm2 = new Sm2Crypto();

                // 1. 生成密钥对
                Console.WriteLine("1. 生成SM2密钥对...");
                var (publicKey, privateKey) = sm2.GenerateKeyPair();
                Console.WriteLine($"公钥长度: {publicKey.Length} 字节");
                Console.WriteLine($"私钥长度: {privateKey.Length} 字节");
                Console.WriteLine($"公钥 (Hex): {BitConverter.ToString(publicKey).Replace("-", "")}");
                Console.WriteLine($"私钥 (Hex): {BitConverter.ToString(privateKey).Replace("-", "")}\n");

                // 2. 验证密钥
                Console.WriteLine("2. 验证密钥格式...");
                var isPublicKeyValid = sm2.ValidateKey(publicKey, false);
                var isPrivateKeyValid = sm2.ValidateKey(privateKey, true);
                Console.WriteLine($"公钥验证结果: {isPublicKeyValid}");
                Console.WriteLine($"私钥验证结果: {isPrivateKeyValid}\n");

                // 3. 从私钥获取公钥
                Console.WriteLine("3. 从私钥获取公钥...");
                var derivedPublicKey = sm2.GetPublicKeyFromPrivateKey(privateKey);
                var isDerivedKeyValid = sm2.ValidateKey(derivedPublicKey, false);
                Console.WriteLine($"派生公钥长度: {derivedPublicKey.Length} 字节");
                Console.WriteLine($"派生公钥验证结果: {isDerivedKeyValid}");
                Console.WriteLine($"派生公钥与原始公钥相同: {BitConverter.ToString(publicKey).Replace("-", "") == BitConverter.ToString(derivedPublicKey).Replace("-", "")}\n");

                // 4. 加密解密测试
                Console.WriteLine("4. 加密解密测试...");
                var originalText = "这是SM2加密测试数据，包含中文字符！";
                var originalData = Encoding.UTF8.GetBytes(originalText);
                Console.WriteLine($"原始数据: {originalText}");
                Console.WriteLine($"原始数据长度: {originalData.Length} 字节");

                // 加密
                var encryptedData = sm2.Encrypt(originalData, publicKey);
                Console.WriteLine($"加密后长度: {encryptedData.Length} 字节");
                Console.WriteLine($"加密数据 (Hex): {BitConverter.ToString(encryptedData).Replace("-", "")}");

                // 解密
                var decryptedData = sm2.Decrypt(encryptedData, privateKey);
                var decryptedText = Encoding.UTF8.GetString(decryptedData);
                Console.WriteLine($"解密后数据: {decryptedText}");
                Console.WriteLine($"解密成功: {originalText == decryptedText}\n");

                // 5. 签名验证测试
                Console.WriteLine("5. 签名验证测试...");
                var messageToSign = "这是SM2签名测试数据！";
                var messageData = Encoding.UTF8.GetBytes(messageToSign);
                Console.WriteLine($"待签名数据: {messageToSign}");

                // 签名
                var signature = sm2.Sign(messageData, privateKey);
                Console.WriteLine($"签名长度: {signature.Length} 字节");
                Console.WriteLine($"签名 (Hex): {BitConverter.ToString(signature).Replace("-", "")}");

                // 验证签名
                var isValidSignature = sm2.VerifySign(messageData, signature, publicKey);
                Console.WriteLine($"签名验证结果: {isValidSignature}");

                // 验证错误签名
                var wrongMessage = Encoding.UTF8.GetBytes("错误的消息");
                var isWrongSignatureValid = sm2.VerifySign(wrongMessage, signature, publicKey);
                Console.WriteLine($"错误消息签名验证结果: {isWrongSignatureValid}\n");

                // 6. 密文格式转换测试
                Console.WriteLine("6. 密文格式转换测试...");
                var format = sm2.DetectCipherFormat(encryptedData);
                Console.WriteLine($"检测到的密文格式: {format}");

                // 获取密文组件信息
                var componentInfo = sm2.GetCipherComponentInfo(encryptedData);
                Console.WriteLine($"密文组件信息: {componentInfo}");

                // 验证密文数据
                var isValidCipher = sm2.ValidateCipherData(encryptedData, format);
                Console.WriteLine($"密文数据验证结果: {isValidCipher}\n");

                // 7. 异步操作测试
                Console.WriteLine("7. 异步操作测试...");
                var asyncEncryptedData = await sm2.EncryptAsync(originalData, publicKey);
                var asyncDecryptedData = await sm2.DecryptAsync(asyncEncryptedData, privateKey);
                var asyncDecryptedText = Encoding.UTF8.GetString(asyncDecryptedData);
                Console.WriteLine($"异步解密结果: {asyncDecryptedText}");
                Console.WriteLine($"异步操作成功: {originalText == asyncDecryptedText}");

                var asyncSignature = await sm2.SignAsync(messageData, privateKey);
                var asyncVerifyResult = await sm2.VerifySignatureAsync(messageData, asyncSignature, publicKey);
                Console.WriteLine($"异步签名验证结果: {asyncVerifyResult}\n");

                Console.WriteLine("=== 所有测试完成 ===");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"测试过程中发生错误: {ex.Message}");
                Console.WriteLine($"错误详情: {ex}");
            }
        }

        /// <summary>
        /// 性能测试
        /// </summary>
        public static void PerformanceTest()
        {
            Console.WriteLine("=== SM2性能测试 ===\n");

            try
            {
                var sm2 = new Sm2Crypto();
                var (publicKey, privateKey) = sm2.GenerateKeyPair();

                // 测试数据
                var testData = Encoding.UTF8.GetBytes("性能测试数据 - " + new string('A', 1000));
                Console.WriteLine($"测试数据长度: {testData.Length} 字节");

                // 加密性能测试
                var startTime = DateTime.Now;
                const int encryptCount = 100;
                
                for (int i = 0; i < encryptCount; i++)
                {
                    var encrypted = sm2.Encrypt(testData, publicKey);
                    var decrypted = sm2.Decrypt(encrypted, privateKey);
                }
                
                var endTime = DateTime.Now;
                var totalTime = endTime - startTime;
                var avgTime = totalTime.TotalMilliseconds / encryptCount;

                Console.WriteLine($"执行 {encryptCount} 次加密解密操作");
                Console.WriteLine($"总耗时: {totalTime.TotalMilliseconds:F2} 毫秒");
                Console.WriteLine($"平均每次操作耗时: {avgTime:F2} 毫秒");
                Console.WriteLine($"每秒可处理操作数: {1000 / avgTime:F0} 次\n");

                // 签名性能测试
                startTime = DateTime.Now;
                const int signCount = 100;
                
                for (int i = 0; i < signCount; i++)
                {
                    var signature = sm2.Sign(testData, privateKey);
                    var isValid = sm2.VerifySign(testData, signature, publicKey);
                }
                
                endTime = DateTime.Now;
                totalTime = endTime - startTime;
                avgTime = totalTime.TotalMilliseconds / signCount;

                Console.WriteLine($"执行 {signCount} 次签名验证操作");
                Console.WriteLine($"总耗时: {totalTime.TotalMilliseconds:F2} 毫秒");
                Console.WriteLine($"平均每次操作耗时: {avgTime:F2} 毫秒");
                Console.WriteLine($"每秒可处理操作数: {1000 / avgTime:F0} 次");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"性能测试过程中发生错误: {ex.Message}");
            }
        }
    }
}
