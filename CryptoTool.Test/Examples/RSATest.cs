using CryptoTool.Algorithm.Algorithms.RSA;
using CryptoTool.Algorithm.Enums;
using CryptoTool.Algorithm.Factory;
using System;
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

                // PKCS格式转换测试
                Console.WriteLine("\n--- PKCS格式转换测试 ---");
                await TestPKCSFormatConversion();

                // PEM格式测试
                await TestRSAPemMethods();

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

        /// <summary>
        /// 测试PKCS格式转换功能
        /// </summary>
        public static async Task TestPKCSFormatConversion()
        {
            var rsa = new RsaCrypto(2048);
            Console.WriteLine("=== PKCS格式转换测试 ===");

            try
            {
                // 生成原始密钥对（默认PKCS1格式）
                var (originalPublicKey, originalPrivateKey) = rsa.GenerateKeyPair();
                Console.WriteLine($"原始公钥长度: {originalPublicKey.Length} 字节");
                Console.WriteLine($"原始私钥长度: {originalPrivateKey.Length} 字节");

                // 测试公钥格式转换
                Console.WriteLine("\n--- 公钥格式转换测试 ---");
                TestPublicKeyConversion(rsa, originalPublicKey);

                // 测试私钥格式转换
                Console.WriteLine("\n--- 私钥格式转换测试 ---");
                TestPrivateKeyConversion(rsa, originalPrivateKey);

                Console.WriteLine("PKCS格式转换测试完成！\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"PKCS格式转换测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }
        }

        /// <summary>
        /// 测试公钥格式转换
        /// </summary>
        private static void TestPublicKeyConversion(RsaCrypto rsa, byte[] originalPublicKey)
        {
            try
            {
                // PKCS1 -> PKCS8
                var pkcs8PublicKey = rsa.ConvertPublicKeyFromPKCS1ToPKCS8(originalPublicKey);
                Console.WriteLine($"✓ PKCS1 -> PKCS8 转换成功，长度: {pkcs8PublicKey.Length} 字节");
                // PKCS8 -> PKCS1
                var pkcs1PublicKey = rsa.ConvertPublicKeyFromPKCS8ToPKCS1(pkcs8PublicKey);
                Console.WriteLine($"✓ PKCS8 -> PKCS1 转换成功，长度: {pkcs1PublicKey.Length} 字节");

                // 验证转换后的密钥是否仍然有效
                var testData = Encoding.UTF8.GetBytes("PKCS格式转换测试数据");
                var encryptedData = rsa.Encrypt(testData, pkcs1PublicKey);
                Console.WriteLine($"✓ 转换后的公钥加密功能正常");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ 公钥格式转换失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试私钥格式转换
        /// </summary>
        private static void TestPrivateKeyConversion(RsaCrypto rsa, byte[] originalPrivateKey)
        {
            try
            {
                // PKCS1 -> PKCS8
                var pkcs8PrivateKey = rsa.ConvertPrivateKeyFromPKCS1ToPKCS8(originalPrivateKey);
                Console.WriteLine($"✓ PKCS1 -> PKCS8 转换成功，长度: {pkcs8PrivateKey.Length} 字节");

                // PKCS8 -> PKCS1
                var pkcs1PrivateKey = rsa.ConvertPrivateKeyFromPKCS8ToPKCS1(pkcs8PrivateKey);
                Console.WriteLine($"✓ PKCS8 -> PKCS1 转换成功，长度: {pkcs1PrivateKey.Length} 字节");


                // 验证转换后的密钥是否仍然有效
                var testData = Encoding.UTF8.GetBytes("PKCS格式转换测试数据");
                var signature = rsa.Sign(testData, pkcs1PrivateKey);
                Console.WriteLine($"✓ 转换后的私钥签名功能正常");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ 私钥格式转换失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试RSA PEM格式功能
        /// </summary>
        public static async Task TestRSAPemMethods()
        {
            Console.WriteLine("=== RSA PEM格式测试 ===");

            try
            {
                // 测试 PKCS1 格式
                await TestPemWithFormat("pkcs1");

                // 测试 PKCS8 格式
                await TestPemWithFormat("pkcs8");

                // 测试 PEM 格式转换
                await TestPemFormatConversion();

                // 测试 PEM 加密解密
                await TestPemEncryptionDecryption();

                // 测试 PEM 签名验签
                await TestPemSignatureVerification();

                Console.WriteLine("RSA PEM格式测试完成！\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA PEM格式测试失败: {ex.Message}");
                Console.WriteLine($"异常详情: {ex}");
            }
        }

        /// <summary>
        /// 测试指定格式的PEM功能
        /// </summary>
        /// <param name="keyFormat">密钥格式</param>
        private static async Task TestPemWithFormat(string keyFormat)
        {
            Console.WriteLine($"\n--- {keyFormat.ToUpper()} 格式 PEM 测试 ---");

            try
            {
                var rsa = new RsaCrypto(2048, keyFormat);

                // 生成PEM格式密钥对
                var (publicKeyPem, privateKeyPem) = rsa.GenerateKeyPairPem();
                Console.WriteLine($"✓ PEM密钥对生成成功 (格式: {keyFormat})");
                Console.WriteLine($"  公钥长度: {publicKeyPem.Length} 字符");
                Console.WriteLine($"  私钥长度: {privateKeyPem.Length} 字符");

                // 验证PEM格式
                ValidatePemFormat(publicKeyPem, keyFormat, true);
                ValidatePemFormat(privateKeyPem, keyFormat, false);

                // 导出为字节数组然后再转为PEM
                var (publicKeyBytes, privateKeyBytes) = rsa.GenerateKeyPair();
                var exportedPublicPem = rsa.ExportPublicKeyToPem(publicKeyBytes);
                var exportedPrivatePem = rsa.ExportPrivateKeyToPem(privateKeyBytes);

                Console.WriteLine($"✓ 字节数组转PEM格式成功");

                // 从PEM导入为字节数组
                var importedPublicBytes = rsa.ImportPublicKeyFromPem(publicKeyPem);
                var importedPrivateBytes = rsa.ImportPrivateKeyFromPem(privateKeyPem);

                Console.WriteLine($"✓ PEM格式转字节数组成功");
                Console.WriteLine($"  导入公钥长度: {importedPublicBytes.Length} 字节");
                Console.WriteLine($"  导入私钥长度: {importedPrivateBytes.Length} 字节");

                // 验证功能正常
                await TestPemFunctionality(rsa, publicKeyPem, privateKeyPem);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ {keyFormat.ToUpper()} 格式测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 验证PEM格式是否正确
        /// </summary>
        /// <param name="pemKey">PEM密钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="isPublicKey">是否为公钥</param>
        private static void ValidatePemFormat(string pemKey, string keyFormat, bool isPublicKey)
        {
            var expectedHeader = keyFormat.ToLower() switch
            {
                "pkcs1" => isPublicKey ? "-----BEGIN RSA PUBLIC KEY-----" : "-----BEGIN RSA PRIVATE KEY-----",
                "pkcs8" => isPublicKey ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----",
                _ => throw new ArgumentException($"不支持的密钥格式: {keyFormat}")
            };

            var expectedFooter = expectedHeader.Replace("BEGIN", "END");

            if (!pemKey.StartsWith(expectedHeader) || !pemKey.Contains(expectedFooter))
            {
                throw new Exception($"PEM格式验证失败，期望格式: {expectedHeader}");
            }

            Console.WriteLine($"✓ PEM格式验证通过 ({(isPublicKey ? "公钥" : "私钥")})");
        }

        /// <summary>
        /// 测试PEM功能是否正常
        /// </summary>
        /// <param name="rsa">RSA实例</param>
        /// <param name="publicKeyPem">PEM公钥</param>
        /// <param name="privateKeyPem">PEM私钥</param>
        private static async Task TestPemFunctionality(RsaCrypto rsa, string publicKeyPem, string privateKeyPem)
        {
            var testData = Encoding.UTF8.GetBytes("PEM格式功能测试数据");

            // 测试加密解密
            var encryptedData = rsa.EncryptWithPem(testData, publicKeyPem);
            var decryptedData = rsa.DecryptWithPem(encryptedData, privateKeyPem);
            var decryptedText = Encoding.UTF8.GetString(decryptedData);

            if (decryptedText == "PEM格式功能测试数据")
            {
                Console.WriteLine($"✓ PEM加密解密功能正常");
            }
            else
            {
                throw new Exception("PEM加密解密功能异常");
            }

            // 测试签名验签
            var signature = rsa.SignWithPem(testData, privateKeyPem);
            var verifyResult = rsa.VerifySignWithPem(testData, signature, publicKeyPem);

            if (verifyResult)
            {
                Console.WriteLine($"✓ PEM签名验签功能正常");
            }
            else
            {
                throw new Exception("PEM签名验签功能异常");
            }
        }

        /// <summary>
        /// 测试PEM格式转换
        /// </summary>
        private static async Task TestPemFormatConversion()
        {
            Console.WriteLine($"\n--- PEM 格式转换测试 ---");

            try
            {
                // 生成PKCS1格式密钥
                var rsaPkcs1 = new RsaCrypto(2048, "pkcs1");
                var (publicPkcs1Pem, privatePkcs1Pem) = rsaPkcs1.GenerateKeyPairPem();

                // 生成PKCS8格式密钥
                var rsaPkcs8 = new RsaCrypto(2048, "pkcs8");
                var (publicPkcs8Pem, privatePkcs8Pem) = rsaPkcs8.GenerateKeyPairPem();

                Console.WriteLine($"✓ 不同格式PEM密钥生成成功");

                // 交叉验证：PKCS1实例能否处理PKCS8的PEM
                try
                {
                    var pkcs8ToBytes = rsaPkcs1.ImportPublicKeyFromPem(publicPkcs8Pem);
                    var bytesToPkcs1 = rsaPkcs1.ExportPublicKeyToPem(pkcs8ToBytes);
                    Console.WriteLine($"✓ PKCS8 PEM 转 PKCS1 PEM 成功");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠ PKCS8 PEM 转 PKCS1 PEM 失败: {ex.Message}");
                }

                // 交叉验证：PKCS8实例能否处理PKCS1的PEM  
                try
                {
                    var pkcs1ToBytes = rsaPkcs8.ImportPublicKeyFromPem(publicPkcs1Pem);
                    var bytesToPkcs8 = rsaPkcs8.ExportPublicKeyToPem(pkcs1ToBytes);
                    Console.WriteLine($"✓ PKCS1 PEM 转 PKCS8 PEM 成功");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠ PKCS1 PEM 转 PKCS8 PEM 失败: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ PEM格式转换测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试PEM加密解密性能
        /// </summary>
        private static async Task TestPemEncryptionDecryption()
        {
            Console.WriteLine($"\n--- PEM 加密解密性能测试 ---");

            try
            {
                var rsa = new RsaCrypto(2048, "pkcs8");
                var (publicKeyPem, privateKeyPem) = rsa.GenerateKeyPairPem();

                // 测试不同大小的数据
                var testSizes = new[] { 10, 50, 100, 200 }; // 字节

                foreach (var size in testSizes)
                {
                    var testData = new byte[size];
                    new Random().NextBytes(testData);

                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                    var encryptedData = rsa.EncryptWithPem(testData, publicKeyPem);
                    var decryptedData = rsa.DecryptWithPem(encryptedData, privateKeyPem);

                    stopwatch.Stop();

                    var isSuccess = testData.SequenceEqual(decryptedData);
                    Console.WriteLine($"  数据大小: {size} 字节, 耗时: {stopwatch.ElapsedMilliseconds} ms, 结果: {(isSuccess ? "成功" : "失败")}");
                }

                Console.WriteLine($"✓ PEM加密解密性能测试完成");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ PEM加密解密性能测试失败: {ex.Message}");
            }
        }

        /// <summary>
        /// 测试PEM签名验签
        /// </summary>
        private static async Task TestPemSignatureVerification()
        {
            Console.WriteLine($"\n--- PEM 签名验签测试 ---");

            try
            {
                var rsa = new RsaCrypto(2048, "pkcs8");
                var (publicKeyPem, privateKeyPem) = rsa.GenerateKeyPairPem();

                var testMessages = new[]
                {
                    "简单测试消息",
                    "包含特殊字符的消息：!@#$%^&*()",
                    "包含中文的消息：你好，世界！",
                    "长消息：" + new string('A', 500)
                };

                foreach (var message in testMessages)
                {
                    var messageBytes = Encoding.UTF8.GetBytes(message);
                    
                    var signature = rsa.SignWithPem(messageBytes, privateKeyPem);
                    var isValid = rsa.VerifySignWithPem(messageBytes, signature, publicKeyPem);

                    Console.WriteLine($"  消息长度: {message.Length} 字符, 签名验证: {(isValid ? "成功" : "失败")}");

                    // 测试篡改数据的验证
                    if (messageBytes.Length > 1)
                    {
                        messageBytes[0] = (byte)(messageBytes[0] ^ 1); // 修改一个字节
                        var isTamperedValid = rsa.VerifySignWithPem(messageBytes, signature, publicKeyPem);
                        
                        if (!isTamperedValid)
                        {
                            Console.WriteLine($"    ✓ 篡改检测正常");
                        }
                        else
                        {
                            Console.WriteLine($"    ✗ 篡改检测异常");
                        }
                    }
                }

                Console.WriteLine($"✓ PEM签名验签测试完成");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"✗ PEM签名验签测试失败: {ex.Message}");
            }
        }
    }
}
