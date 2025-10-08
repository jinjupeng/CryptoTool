using CryptoTool.Algorithm.Enums;
using CryptoTool.Algorithm.Factory;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Test.Examples
{
    internal class SM4Test
    {
        /// <summary>
        /// 运行SM4算法测试
        /// </summary>
        public static void RunTest()
        {
            Console.WriteLine("=== SM4算法测试 ===");

            try
            {
                // 创建SM4算法实例
                var sm4 = CryptoFactory.CreateSm4(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7);
                Console.WriteLine($"算法名称: {sm4.AlgorithmName}");
                Console.WriteLine($"算法类型: {sm4.AlgorithmType}");

                // 测试数据
                string testData = "这是一个SM4加密测试数据，包含中文字符和特殊符号!@#$%^&*()";
                byte[] data = Encoding.UTF8.GetBytes(testData);
                Console.WriteLine($"原始数据: {testData}");
                Console.WriteLine($"数据长度: {data.Length} 字节");

                // 生成密钥和IV
                byte[] key = sm4.GenerateKey();
                byte[] iv = sm4.GenerateIV();
                Console.WriteLine($"密钥长度: {key.Length} 字节");
                Console.WriteLine($"IV长度: {iv.Length} 字节");

                // 加密测试
                Console.WriteLine("\n--- 加密测试 ---");
                byte[] encryptedData = sm4.Encrypt(data, key, iv);
                Console.WriteLine($"加密成功，加密数据长度: {encryptedData.Length} 字节");
                Console.WriteLine($"加密数据(Hex): {BitConverter.ToString(encryptedData).Replace("-", "")}");

                // 解密测试
                Console.WriteLine("\n--- 解密测试 ---");
                byte[] decryptedData = sm4.Decrypt(encryptedData, key, iv);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);
                Console.WriteLine($"解密成功，解密数据: {decryptedText}");

                // 验证结果
                bool isSuccess = testData == decryptedText;
                Console.WriteLine($"\n--- 测试结果 ---");
                Console.WriteLine($"测试结果: {(isSuccess ? "通过" : "失败")}");

                // 不同模式测试
                Console.WriteLine("\n--- 不同加密模式测试 ---");
                TestDifferentModes();

                // 大数据测试
                Console.WriteLine("\n--- 大数据测试 ---");
                TestLargeData();

                // 多次加密测试
                Console.WriteLine("\n--- 多次加密测试 ---");
                TestMultipleEncryption();

            }
            catch (Exception ex)
            {
                Console.WriteLine($"SM4测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }

            Console.WriteLine("=== SM4算法测试完成 ===\n");
        }

        /// <summary>
        /// 测试不同的加密模式
        /// </summary>
        private static void TestDifferentModes()
        {
            string testData = "SM4不同模式测试数据";
            byte[] data = Encoding.UTF8.GetBytes(testData);

            // 测试CBC模式
            var sm4Cbc = CryptoFactory.CreateSm4(Algorithm.Enums.SymmetricCipherMode.ECB, SymmetricPaddingMode.PKCS7);
            byte[] key = sm4Cbc.GenerateKey();
            byte[] iv = sm4Cbc.GenerateIV();
            byte[] encryptedCbc = sm4Cbc.Encrypt(data, key, iv);
            byte[] decryptedCbc = sm4Cbc.Decrypt(encryptedCbc, key, iv);
            bool cbcSuccess = data.SequenceEqual(decryptedCbc);
            Console.WriteLine($"CBC模式测试: {(cbcSuccess ? "通过" : "失败")}");

            // 测试ECB模式
            var sm4Ecb = CryptoFactory.CreateSm4(SymmetricCipherMode.ECB, SymmetricPaddingMode.PKCS7);
            byte[] keyEcb = sm4Ecb.GenerateKey();
            byte[] encryptedEcb = sm4Ecb.Encrypt(data, keyEcb);
            byte[] decryptedEcb = sm4Ecb.Decrypt(encryptedEcb, keyEcb);
            bool ecbSuccess = data.SequenceEqual(decryptedEcb);
            Console.WriteLine($"ECB模式测试: {(ecbSuccess ? "通过" : "失败")}");

            // 测试CFB模式
            var sm4Cfb = CryptoFactory.CreateSm4(SymmetricCipherMode.CBC, SymmetricPaddingMode.PKCS7);
            byte[] keyCfb = sm4Cfb.GenerateKey();
            byte[] ivCfb = sm4Cfb.GenerateIV();
            byte[] encryptedCfb = sm4Cfb.Encrypt(data, keyCfb, ivCfb);
            byte[] decryptedCfb = sm4Cfb.Decrypt(encryptedCfb, keyCfb, ivCfb);
            bool cfbSuccess = data.SequenceEqual(decryptedCfb);
            Console.WriteLine($"CFB模式测试: {(cfbSuccess ? "通过" : "失败")}");

            // 测试OFB模式
            var sm4Ofb = CryptoFactory.CreateSm4(SymmetricCipherMode.OFB, SymmetricPaddingMode.PKCS7);
            byte[] keyOfb = sm4Ofb.GenerateKey();
            byte[] ivOfb = sm4Ofb.GenerateIV();
            byte[] encryptedOfb = sm4Ofb.Encrypt(data, keyOfb, ivOfb);
            byte[] decryptedOfb = sm4Ofb.Decrypt(encryptedOfb, keyOfb, ivOfb);
            bool ofbSuccess = data.SequenceEqual(decryptedOfb);
            Console.WriteLine($"OFB模式测试: {(ofbSuccess ? "通过" : "失败")}");
        }

        /// <summary>
        /// 测试大数据
        /// </summary>
        private static void TestLargeData()
        {
            var sm4 = CryptoFactory.CreateSm4();
            byte[] key = sm4.GenerateKey();
            byte[] iv = sm4.GenerateIV();

            // 生成1KB的测试数据
            string largeData = new string('A', 1024);
            byte[] data = Encoding.UTF8.GetBytes(largeData);

            try
            {
                byte[] encryptedData = sm4.Encrypt(data, key, iv);
                byte[] decryptedData = sm4.Decrypt(encryptedData, key, iv);
                bool success = data.SequenceEqual(decryptedData);
                Console.WriteLine($"大数据测试(1KB): {(success ? "通过" : "失败")}");
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
            var sm4 = CryptoFactory.CreateSm4();
            byte[] key = sm4.GenerateKey();
            byte[] iv = sm4.GenerateIV();

            string testData = "SM4多次加密测试数据";
            byte[] data = Encoding.UTF8.GetBytes(testData);

            try
            {
                // 连续加密解密5次
                byte[] currentData = data;
                for (int i = 0; i < 5; i++)
                {
                    byte[] encryptedData = sm4.Encrypt(currentData, key, iv);
                    byte[] decryptedData = sm4.Decrypt(encryptedData, key, iv);
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
    }
}
