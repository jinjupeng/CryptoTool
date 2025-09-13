# CryptoTool.Algorithm

一个完整的C#加密算法类库，支持多种加密、哈希和国密算法，兼容.NET Standard 2.1。

## 支持的算法

### 对称加密算法
- **AES** (Advanced Encryption Standard) - 支持128/192/256位密钥
- **DES** (Data Encryption Standard) - 64位密钥
- **SM4** - 国密对称加密算法，128位密钥

### 非对称加密算法
- **RSA** - 支持1024/2048/4096位密钥
- **SM2** - 国密非对称加密算法

### 哈希算法
- **MD5** - 128位哈希值
- **SM3** - 国密哈希算法，256位哈希值

## 快速开始

### 1. 安装

```xml
<PackageReference Include="CryptoTool.Algorithm" Version="1.0.0" />
```

### 2. 基本使用

```csharp
using CryptoTool.Algorithm;

// 字符串转字节数组
string text = "Hello, 加密算法类库!";
byte[] data = CryptoTool.StringToBytes(text);

// AES加密
byte[] key = CryptoTool.GenerateRandomKey(256);
byte[] encrypted = CryptoTool.AesEncrypt(data, key);
byte[] decrypted = CryptoTool.AesDecrypt(encrypted, key);
string result = CryptoTool.BytesToString(decrypted);

// MD5哈希
byte[] hash = CryptoTool.Md5Hash(data);
string hashHex = CryptoTool.BytesToHex(hash, true);
```

## 详细使用说明

### 对称加密

#### AES加密
```csharp
// 生成随机密钥和IV
byte[] key = CryptoTool.GenerateRandomKey(256);
byte[] iv = CryptoTool.GenerateRandomIV(128);

// 加密
byte[] encrypted = CryptoTool.AesEncrypt(data, key, iv);

// 解密
byte[] decrypted = CryptoTool.AesDecrypt(encrypted, key, iv);
```

#### DES加密
```csharp
byte[] key = CryptoTool.GenerateRandomKey(64);
byte[] encrypted = CryptoTool.DesEncrypt(data, key);
byte[] decrypted = CryptoTool.DesDecrypt(encrypted, key);
```

#### SM4国密加密
```csharp
byte[] key = CryptoTool.GenerateRandomKey(128);
byte[] encrypted = CryptoTool.Sm4Encrypt(data, key);
byte[] decrypted = CryptoTool.Sm4Decrypt(encrypted, key);
```

### 非对称加密

#### RSA加密
```csharp
// 生成密钥对
var (publicKey, privateKey) = CryptoTool.RsaGenerateKeyPair(2048);

// 加密
byte[] encrypted = CryptoTool.RsaEncrypt(data, publicKey);

// 解密
byte[] decrypted = CryptoTool.RsaDecrypt(encrypted, privateKey);

// 签名
byte[] signature = CryptoTool.RsaSign(data, privateKey);

// 验证签名
bool isValid = CryptoTool.RsaVerifySignature(data, signature, publicKey);
```

#### SM2国密加密
```csharp
// 生成密钥对
var (publicKey, privateKey) = CryptoTool.Sm2GenerateKeyPair();

// 加密
byte[] encrypted = CryptoTool.Sm2Encrypt(data, publicKey);

// 解密
byte[] decrypted = CryptoTool.Sm2Decrypt(encrypted, privateKey);

// 签名
byte[] signature = CryptoTool.Sm2Sign(data, privateKey);

// 验证签名
bool isValid = CryptoTool.Sm2VerifySignature(data, signature, publicKey);
```

#### SM2密文格式转换
```csharp
// C1C2C3格式转C1C3C2格式
byte[] c1c3c2Data = CryptoTool.Sm2ConvertC1C2C3ToC1C3C2(c1c2c3Data);

// C1C3C2格式转C1C2C3格式
byte[] c1c2c3Data = CryptoTool.Sm2ConvertC1C3C2ToC1C2C3(c1c3c2Data);

// 检测密文格式
var format = CryptoTool.Sm2DetectCipherFormat(cipherData);

// 验证密文数据完整性
bool isValid = CryptoTool.Sm2ValidateCipherData(cipherData, expectedFormat);

// 获取密文组件信息
var info = CryptoTool.Sm2GetCipherComponentInfo(cipherData);
```

### 哈希算法

#### MD5哈希
```csharp
byte[] hash = CryptoTool.Md5Hash(data);
string hashHex = CryptoTool.Md5HashString(data, true);
```

#### SM3国密哈希
```csharp
byte[] hash = CryptoTool.Sm3Hash(data);
string hashHex = CryptoTool.Sm3HashString(data, true);
```

### 工具方法

```csharp
// 字节数组和十六进制字符串转换
string hex = CryptoTool.BytesToHex(data, true);
byte[] fromHex = CryptoTool.HexToBytes(hex);

// Base64编码解码
string base64 = CryptoTool.BytesToBase64(data);
byte[] fromBase64 = CryptoTool.Base64ToBytes(base64);

// 字符串和字节数组转换
byte[] data = CryptoTool.StringToBytes("Hello");
string text = CryptoTool.BytesToString(data);
```

## 工厂模式使用

```csharp
using CryptoTool.Algorithm.Factory;

// 创建算法实例
var aes = CryptoFactory.CreateAes(256);
var rsa = CryptoFactory.CreateRsa(2048);
var md5 = CryptoFactory.CreateMd5();
var sm2 = CryptoFactory.CreateSm2();
var sm3 = CryptoFactory.CreateSm3();
var sm4 = CryptoFactory.CreateSm4();

// 获取支持的算法列表
var algorithms = CryptoFactory.GetSupportedAlgorithms();

// 检查算法是否支持
bool isSupported = CryptoFactory.IsSupported("AES");
```

## 异步支持

所有算法都支持异步操作：

```csharp
// 异步AES加密
byte[] encrypted = await CryptoTool.AesEncryptAsync(data, key);

// 异步RSA加密
byte[] encrypted = await CryptoTool.RsaEncryptAsync(data, publicKey);

// 异步哈希计算
byte[] hash = await CryptoTool.Md5HashAsync(data);

// 异步SM2密文格式转换
byte[] c1c3c2Data = await CryptoTool.Sm2ConvertC1C2C3ToC1C3C2Async(c1c2c3Data);
byte[] c1c2c3Data = await CryptoTool.Sm2ConvertC1C3C2ToC1C2C3Async(c1c3c2Data);
var format = await CryptoTool.Sm2DetectCipherFormatAsync(cipherData);
```

## 高级功能

### 密码派生密钥

```csharp
using CryptoTool.Algorithm.Algorithms.AES;

var aes = new AesCrypto();
var (key, salt) = aes.DeriveKeyFromPassword("password123");
```

### 文件哈希计算

```csharp
using CryptoTool.Algorithm.Algorithms.MD5;

var md5 = new Md5Hash();
byte[] fileHash = md5.ComputeFileHash("path/to/file.txt");
string fileHashHex = md5.ComputeFileHashString("path/to/file.txt", true);
```

### HMAC计算

```csharp
using CryptoTool.Algorithm.Algorithms.SM3;

var sm3 = new Sm3Hash();
byte[] hmac = sm3.ComputeHmac(data, key);
string hmacHex = sm3.ComputeHmacString(data, key, true);
```

### SM2密文格式转换

```csharp
using CryptoTool.Algorithm.Utils;

// 直接使用转换器
byte[] c1c3c2Data = Sm2CipherFormatConverter.ConvertC1C2C3ToC1C3C2(c1c2c3Data);
byte[] c1c2c3Data = Sm2CipherFormatConverter.ConvertC1C3C2ToC1C2C3(c1c3c2Data);

// 检测密文格式
var format = Sm2CipherFormatConverter.DetectFormat(cipherData);

// 获取密文组件信息
var info = Sm2CipherFormatConverter.GetComponentInfo(cipherData);
Console.WriteLine($"格式: {info.FormatString}, C1: {info.C1Length}字节, C2: {info.C2Length}字节, C3: {info.C3Length}字节");
```

## 异常处理

类库提供了详细的异常类型：

- `CryptoException` - 加密算法异常基类
- `KeyException` - 密钥相关异常
- `DataException` - 数据相关异常
- `AlgorithmNotSupportedException` - 算法不支持异常

```csharp
try
{
    byte[] encrypted = CryptoTool.AesEncrypt(data, key);
}
catch (KeyException ex)
{
    Console.WriteLine($"密钥错误: {ex.Message}");
}
catch (DataException ex)
{
    Console.WriteLine($"数据错误: {ex.Message}");
}
catch (CryptoException ex)
{
    Console.WriteLine($"加密错误: {ex.Message}");
}
```

## 性能优化

- 所有算法都支持异步操作
- 使用对象池减少GC压力
- 支持流式处理大文件
- 内存安全的字节数组操作

## 安全建议

1. **密钥管理**: 使用安全的密钥存储方案
2. **随机数**: 使用强随机数生成器
3. **算法选择**: 根据安全需求选择合适的算法
4. **密钥长度**: 使用足够长的密钥
5. **填充模式**: 选择合适的填充模式

## 依赖项

- .NET Standard 2.1
- System.Security.Cryptography.Algorithms
- System.Security.Cryptography.Cng
- System.Security.Cryptography.OpenSsl
- Portable.BouncyCastle

## 许可证

MIT License

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 更新日志

### v1.1.0
- 新增SM2密文格式转换功能
- 支持C1C2C3和C1C3C2格式互转
- 添加密文格式检测和验证功能
- 提供密文组件信息分析
- 支持异步密文格式转换操作

### v1.0.0
- 初始版本发布
- 支持RSA、AES、DES、MD5、SM2、SM3、SM4算法
- 提供完整的API和工具方法
- 支持异步操作
- 包含详细的使用示例
