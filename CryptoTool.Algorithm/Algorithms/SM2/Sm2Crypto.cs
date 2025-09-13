using CryptoTool.Algorithm.Exceptions;
using CryptoTool.Algorithm.Interfaces;
using System;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Signers;

namespace CryptoTool.Algorithm.Algorithms.SM2
{
    /// <summary>
    /// SM2国密算法实现
    /// 基于BouncyCastle库的生产级实现
    /// </summary>
    public class Sm2Crypto : IAsymmetricCrypto
    {
        public string AlgorithmName => "SM2";
        public CryptoAlgorithmType AlgorithmType => CryptoAlgorithmType.Asymmetric;


        /// <summary>
        /// SM2签名算法名称
        /// </summary>
        private const string SM3_WITH_SM2 = "SM3withSM2";

        /// <summary>
        /// SM2曲线名称
        /// </summary>
        private const string SM2_CURVE_NAME = "SM2P256v1";

        /// <summary>
        /// SM2椭圆曲线参数
        /// </summary>
        private static readonly X9ECParameters _sm2Parameters = ECNamedCurveTable.GetByName(SM2_CURVE_NAME);
        private static readonly ECDomainParameters _domainParameters = new ECDomainParameters(_sm2Parameters.Curve, _sm2Parameters.G, _sm2Parameters.N, _sm2Parameters.H, _sm2Parameters.GetSeed());

        /// <summary>
        /// 初始化SM2加密算法
        /// </summary>
        public Sm2Crypto()
        {
        }

        /// <summary>
        /// 加密
        /// </summary>
        public byte[] Encrypt(byte[] data, byte[] publicKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待加密数据不能为空");

            if (publicKey == null || publicKey.Length == 0)
                throw new Exceptions.KeyException("公钥不能为空");

            try
            {
                // 解析公钥
                var ecPublicKey = ParsePublicKey(publicKey);
                
                // 创建SM2加密引擎
                var sm2Engine = new SM2Engine();
                sm2Engine.Init(true, new ParametersWithRandom(ecPublicKey, new SecureRandom()));
                
                // 执行加密
                var encryptedData = sm2Engine.ProcessBlock(data, 0, data.Length);
                
                return encryptedData;
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("SM2加密失败", ex);
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        public byte[] Decrypt(byte[] encryptedData, byte[] privateKey)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new DataException("待解密数据不能为空");

            if (privateKey == null || privateKey.Length == 0)
                throw new Exceptions.KeyException("私钥不能为空");

            try
            {
                // 解析私钥
                var ecPrivateKey = ParsePrivateKey(privateKey);
                
                // 创建SM2加密引擎
                var sm2Engine = new SM2Engine();
                sm2Engine.Init(false, ecPrivateKey);
                
                // 执行解密
                var decryptedData = sm2Engine.ProcessBlock(encryptedData, 0, encryptedData.Length);
                
                return decryptedData;
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("SM2解密失败", ex);
            }
        }

        /// <summary>
        /// 生成密钥对
        /// </summary>
        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            try
            {
                // 创建密钥生成器
                var keyPairGenerator = new ECKeyPairGenerator();
                var keyGenParams = new ECKeyGenerationParameters(_domainParameters, new SecureRandom());
                keyPairGenerator.Init(keyGenParams);
                
                // 生成密钥对
                var keyPair = keyPairGenerator.GenerateKeyPair();
                var privateKey = (ECPrivateKeyParameters)keyPair.Private;
                var publicKey = (ECPublicKeyParameters)keyPair.Public;
                
                // 转换为字节数组
                var privateKeyBytes = privateKey.D.ToByteArrayUnsigned();
                var publicKeyBytes = EncodePublicKey(publicKey);
                
                return (publicKeyBytes, privateKeyBytes);
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("SM2密钥对生成失败", ex);
            }
        }

        /// <summary>
        /// 签名
        /// </summary>
        public byte[] Sign(byte[] data, byte[] privateKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待签名数据不能为空");

            if (privateKey == null || privateKey.Length == 0)
                throw new Exceptions.KeyException("私钥不能为空");

            try
            {
                // 解析私钥
                var ecPrivateKey = ParsePrivateKey(privateKey);

                // 创建SM2签名器
                var signer = new SM2Signer();
                signer.Init(true, new ParametersWithRandom(ecPrivateKey, new SecureRandom()));

                // 执行签名
                signer.BlockUpdate(data, 0, data.Length);
                var signature = signer.GenerateSignature();
                
                // 如果长度不是64字节，需要调整
                if (signature.Length == 64)
                {
                    return signature;
                }
                else if (signature.Length == 128)
                {
                    // 如果是128字节，取前64字节
                    var result = new byte[64];
                    Array.Copy(signature, 0, result, 0, 64);
                    return result;
                }
                else
                {
                    // 其他情况，尝试解析为r和s值
                    // 对于SM2，签名通常是DER编码的ASN.1格式
                    // 我们需要解析DER格式并提取r和s值
                    try
                    {
                        // 尝试解析为DER格式
                        var derSequence = Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(signature) as Org.BouncyCastle.Asn1.DerSequence;
                        if (derSequence != null && derSequence.Count == 2)
                        {
                            var rDer = derSequence[0] as Org.BouncyCastle.Asn1.DerInteger;
                            var sDer = derSequence[1] as Org.BouncyCastle.Asn1.DerInteger;
                            
                            if (rDer != null && sDer != null)
                            {
                                var rBytes = rDer.Value.ToByteArrayUnsigned();
                                var sBytes = sDer.Value.ToByteArrayUnsigned();
                                
                                // 确保r和s都是32字节
                                var rArray = new byte[32];
                                var sArray = new byte[32];
                                
                                if (rBytes.Length <= 32)
                                {
                                    Array.Copy(rBytes, 0, rArray, 32 - rBytes.Length, rBytes.Length);
                                }
                                else
                                {
                                    Array.Copy(rBytes, rBytes.Length - 32, rArray, 0, 32);
                                }
                                
                                if (sBytes.Length <= 32)
                                {
                                    Array.Copy(sBytes, 0, sArray, 32 - sBytes.Length, sBytes.Length);
                                }
                                else
                                {
                                    Array.Copy(sBytes, sBytes.Length - 32, sArray, 0, 32);
                                }
                                
                                var derResult = new byte[64];
                                Array.Copy(rArray, 0, derResult, 0, 32);
                                Array.Copy(sArray, 0, derResult, 32, 32);
                                
                                return derResult;
                            }
                        }
                    }
                    catch
                    {
                        // 如果DER解析失败，尝试其他方法
                    }
                    
                    // 如果DER解析失败，尝试按长度处理
                    var halfLength = signature.Length / 2;
                    
                    // 验证签名长度是否合理
                    if (signature.Length % 2 != 0 || halfLength < 1 || halfLength > 32)
                    {
                        throw new Exceptions.CryptoException($"不支持的签名长度: {signature.Length}字节，期望64字节或有效的DER格式");
                    }
                    
                    var r = new byte[32];
                    var s = new byte[32];
                    
                    // 安全地复制r和s值，确保不会越界
                    if (halfLength <= 32)
                    {
                        // 右对齐填充到32字节
                        Array.Copy(signature, 0, r, 32 - halfLength, halfLength);
                        Array.Copy(signature, halfLength, s, 32 - halfLength, halfLength);
                    }
                    else
                    {
                        // 如果halfLength > 32，取后32字节
                        Array.Copy(signature, halfLength - 32, r, 0, 32);
                        Array.Copy(signature, halfLength + halfLength - 32, s, 0, 32);
                    }
                    
                    var result = new byte[64];
                    Array.Copy(r, 0, result, 0, 32);
                    Array.Copy(s, 0, result, 32, 32);
                    
                    return result;
                }
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("SM2签名失败", ex);
            }
        }

        /// <summary>
        /// 验证签名
        /// </summary>
        public bool VerifySign(byte[] data, byte[] signature, byte[] publicKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("原始数据不能为空");

            if (signature == null || signature.Length == 0)
                throw new DataException("签名数据不能为空");

            if (publicKey == null || publicKey.Length == 0)
                throw new Exceptions.KeyException("公钥不能为空");

            try
            {
                // 解析公钥
                var ecPublicKey = ParsePublicKey(publicKey);
                
                // 解析签名
                if (signature.Length != 64)
                    return false;
                
                // 将64字节的r||s格式转换为DER格式
                var derSignature = ConvertRsToDer(signature);
                
                // 创建SM2签名器
                var signer = new SM2Signer();
                signer.Init(false, ecPublicKey);
                
                // 执行验证
                signer.BlockUpdate(data, 0, data.Length);
                return signer.VerifySignature(derSignature);
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("SM2签名验证失败", ex);
            }
        }

        /// <summary>
        /// 异步加密
        /// </summary>
        public async Task<byte[]> EncryptAsync(byte[] data, byte[] publicKey)
        {
            return await Task.Run(() => Encrypt(data, publicKey));
        }

        /// <summary>
        /// 异步解密
        /// </summary>
        public async Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] privateKey)
        {
            return await Task.Run(() => Decrypt(encryptedData, privateKey));
        }

        /// <summary>
        /// 异步签名
        /// </summary>
        public async Task<byte[]> SignAsync(byte[] data, byte[] privateKey)
        {
            return await Task.Run(() => Sign(data, privateKey));
        }

        /// <summary>
        /// 异步验证签名
        /// </summary>
        public async Task<bool> VerifySignAsync(byte[] data, byte[] signature, byte[] publicKey)
        {
            return await Task.Run(() => VerifySign(data, signature, publicKey));
        }

        /// <summary>
        /// 从私钥获取公钥
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns>公钥</returns>
        public byte[] GetPublicKeyFromPrivateKey(byte[] privateKey)
        {
            if (privateKey == null || privateKey.Length == 0)
                throw new Exceptions.KeyException("私钥不能为空");

            try
            {
                // 解析私钥
                var ecPrivateKey = ParsePrivateKey(privateKey);
                
                // 计算公钥
                var publicPoint = _domainParameters.G.Multiply(ecPrivateKey.D);
                var publicKey = new ECPublicKeyParameters(publicPoint, _domainParameters);
                
                // 编码公钥
                return EncodePublicKey(publicKey);
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("从私钥获取公钥失败", ex);
            }
        }

        /// <summary>
        /// 验证密钥格式
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <returns>验证结果</returns>
        public bool ValidateKey(byte[] key, bool isPrivateKey)
        {
            if (key == null || key.Length == 0)
                return false;

            try
            {
                if (isPrivateKey)
                {
                    // 验证私钥
                    var privateKey = ParsePrivateKey(key);
                    return privateKey != null && privateKey.D.CompareTo(BigInteger.Zero) > 0 && 
                           privateKey.D.CompareTo(_domainParameters.N) < 0;
                }
                else
                {
                    // 验证公钥
                    var publicKey = ParsePublicKey(key);
                    return publicKey != null && publicKey.Q.IsValid();
                }
            }
            catch
            {
                return false;
            }
        }

        #region 密文格式转换功能

        /// <summary>
        /// 将C1C2C3格式转换为C1C3C2格式
        /// </summary>
        /// <param name="c1c2c3Data">C1C2C3格式的密文数据</param>
        /// <returns>C1C3C2格式的密文数据</returns>
        public byte[] C1C2C3ToC1C3C2(byte[] c1c2c3Data)
        {
            return Sm2CipherFormatConverter.C1C2C3ToC1C3C2(c1c2c3Data);
        }

        /// <summary>
        /// 将C1C3C2格式转换为C1C2C3格式
        /// </summary>
        /// <param name="c1c3c2Data">C1C3C2格式的密文数据</param>
        /// <returns>C1C2C3格式的密文数据</returns>
        public byte[] C1C3C2ToC1C2C3(byte[] c1c3c2Data)
        {
            return Sm2CipherFormatConverter.C1C3C2ToC1C2C3(c1c3c2Data);
        }

        /// <summary>
        /// 检测密文格式
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <returns>密文格式</returns>
        public SM2CipherFormat DetectCipherFormat(byte[] cipherData)
        {
            return Sm2CipherFormatConverter.DetectFormat(cipherData);
        }

        /// <summary>
        /// 验证密文数据完整性
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <param name="expectedFormat">期望的格式</param>
        /// <returns>是否有效</returns>
        public bool ValidateCipherData(byte[] cipherData, SM2CipherFormat expectedFormat)
        {
            return Sm2CipherFormatConverter.ValidateCipherData(cipherData, expectedFormat);
        }

        /// <summary>
        /// 获取密文组件信息
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <returns>组件信息</returns>
        public SM2CipherComponentInfo GetCipherComponentInfo(byte[] cipherData)
        {
            return Sm2CipherFormatConverter.GetComponentInfo(cipherData);
        }

        /// <summary>
        /// 异步转换C1C2C3格式为C1C3C2格式
        /// </summary>
        /// <param name="c1c2c3Data">C1C2C3格式的密文数据</param>
        /// <returns>C1C3C2格式的密文数据</returns>
        public async Task<byte[]> C1C2C3ToC1C3C2Async(byte[] c1c2c3Data)
        {
            return await Task.Run(() => C1C2C3ToC1C3C2(c1c2c3Data));
        }

        /// <summary>
        /// 异步转换C1C3C2格式为C1C2C3格式
        /// </summary>
        /// <param name="c1c3c2Data">C1C3C2格式的密文数据</param>
        /// <returns>C1C2C3格式的密文数据</returns>
        public async Task<byte[]> C1C3C2ToC1C2C3Async(byte[] c1c3c2Data)
        {
            return await Task.Run(() => C1C3C2ToC1C2C3(c1c3c2Data));
        }

        /// <summary>
        /// 异步检测密文格式
        /// </summary>
        /// <param name="cipherData">密文数据</param>
        /// <returns>密文格式</returns>
        public async Task<SM2CipherFormat> DetectCipherFormatAsync(byte[] cipherData)
        {
            return await Task.Run(() => DetectCipherFormat(cipherData));
        }

        #endregion

        #region 私有辅助方法

        /// <summary>
        /// 解析公钥
        /// </summary>
        /// <param name="publicKeyBytes">公钥字节数组</param>
        /// <returns>EC公钥参数</returns>
        private ECPublicKeyParameters ParsePublicKey(byte[] publicKeyBytes)
        {
            try
            {
                // 支持两种格式：压缩格式(33字节)和未压缩格式(65字节)
                if (publicKeyBytes.Length == 33)
                {
                    // 压缩格式
                    var point = _domainParameters.Curve.DecodePoint(publicKeyBytes);
                    return new ECPublicKeyParameters(point, _domainParameters);
                }
                else if (publicKeyBytes.Length == 65)
                {
                    // 未压缩格式
                    var point = _domainParameters.Curve.DecodePoint(publicKeyBytes);
                    return new ECPublicKeyParameters(point, _domainParameters);
                }
                else
                {
                    throw new Exceptions.KeyException($"不支持的公钥长度: {publicKeyBytes.Length}");
                }
            }
            catch (Exception ex)
            {
                throw new Exceptions.KeyException("公钥解析失败", ex);
            }
        }

        /// <summary>
        /// 解析私钥
        /// </summary>
        /// <param name="privateKeyBytes">私钥字节数组</param>
        /// <returns>EC私钥参数</returns>
        private ECPrivateKeyParameters ParsePrivateKey(byte[] privateKeyBytes)
        {
            try
            {
                var d = new BigInteger(1, privateKeyBytes);
                return new ECPrivateKeyParameters(d, _domainParameters);
            }
            catch (Exception ex)
            {
                throw new Exceptions.KeyException("私钥解析失败", ex);
            }
        }

        /// <summary>
        /// 编码公钥
        /// </summary>
        /// <param name="publicKey">EC公钥参数</param>
        /// <returns>公钥字节数组</returns>
        private byte[] EncodePublicKey(ECPublicKeyParameters publicKey)
        {
            try
            {
                // 使用未压缩格式编码公钥
                return publicKey.Q.GetEncoded(false);
            }
            catch (Exception ex)
            {
                throw new Exceptions.KeyException("公钥编码失败", ex);
            }
        }

        /// <summary>
        /// 将r||s格式的签名转换为DER格式
        /// </summary>
        /// <param name="rsSignature">r||s格式的签名（64字节）</param>
        /// <returns>DER格式的签名</returns>
        private byte[] ConvertRsToDer(byte[] rsSignature)
        {
            if (rsSignature == null || rsSignature.Length != 64)
                throw new ArgumentException("签名必须是64字节的r||s格式");

            try
            {
                // 提取r和s值（各32字节）
                var rBytes = new byte[32];
                var sBytes = new byte[32];
                Array.Copy(rsSignature, 0, rBytes, 0, 32);
                Array.Copy(rsSignature, 32, sBytes, 0, 32);

                // 创建BigInteger对象
                var r = new BigInteger(1, rBytes);
                var s = new BigInteger(1, sBytes);

                // 创建DER序列
                var rDer = new Org.BouncyCastle.Asn1.DerInteger(r);
                var sDer = new Org.BouncyCastle.Asn1.DerInteger(s);
                var sequence = new Org.BouncyCastle.Asn1.DerSequence(rDer, sDer);

                // 编码为DER格式
                return sequence.GetEncoded();
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("签名格式转换失败", ex);
            }
        }

        #endregion
    }
}