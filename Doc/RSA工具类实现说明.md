# RSA工具类实现说明

## 概述

本次实现了一个功能完整的RSA工具类 `RSAUtil`，兼容 `.NET Standard 2.1` 框架，支持密钥生成、格式转换、加解密、签名验签、证书处理等完整功能。

## 主要功能特性

### 1. 密钥生成
- **支持密钥长度**：1024、2048、4096位
- **密钥输出类型**：PEM、Base64、Hex
- **密钥格式**：PKCS#1、PKCS#8
- **密钥互转**：支持PKCS#1和PKCS#8格式互相转换

### 2. 加解密功能
- **填充方式**：PKCS#1、OAEP、NoPadding
- **输入格式**：String、Base64、Hex
- **输出格式**：Base64、Hex
- **字符集支持**：UTF-8、GBK、Unicode等

### 3. 签名验签
- **支持算法**：
  - SHA1withRSA
  - SHA256withRSA (推荐)
  - SHA384withRSA
  - SHA512withRSA
  - MD5withRSA
- **输入输出格式**：支持String、Base64、Hex及字节数组
- **字符集支持**：UTF-8、GBK等

### 4. 证书处理
- **生成自签名证书**：支持自定义主题、有效期和签名算法
- **证书导入导出**：支持PEM格式导入导出
- **从证书提取密钥**：支持从X509证书中提取公钥和私钥

### 5. 向后兼容
- **兼容旧接口**：保持对原有接口的兼容性
- **RSA类型枚举**：支持RSA和RSA2类型区分

## 类结构说明

### 核心枚举
```csharp
public enum RSAKeyFormat { PKCS1, PKCS8 }        // 密钥格式
public enum RSAPadding { PKCS1, OAEP, NoPadding } // 填充方式
public enum OutputFormat { PEM, Base64, Hex }     // 输出格式
public enum InputFormat { String, Base64, Hex }   // 输入格式
public enum SignatureAlgorithm { SHA1withRSA, SHA256withRSA, SHA384withRSA, SHA512withRSA, MD5withRSA } // 签名算法
public enum RSAType { RSA, RSA2 }                 // RSA类型（向后兼容）
```

### 主要方法

#### 密钥生成
```csharp
// 生成密钥对
AsymmetricCipherKeyPair GenerateKeyPair(int keySize = 2048)

// 生成公钥字符串
string GeneratePublicKeyString(RsaKeyParameters publicKey, OutputFormat format, RSAKeyFormat keyFormat)

// 生成私钥字符串
string GeneratePrivateKeyString(RsaPrivateCrtKeyParameters privateKey, OutputFormat format, RSAKeyFormat keyFormat)
```

#### 格式转换
```csharp
// PEM格式转换
string PublicKeyToPem(RsaKeyParameters publicKey, RSAKeyFormat keyFormat)
string PrivateKeyToPem(RsaPrivateCrtKeyParameters privateKey, RSAKeyFormat keyFormat)

// Base64格式转换
string PublicKeyToBase64(RsaKeyParameters publicKey, RSAKeyFormat keyFormat)
string PrivateKeyToBase64(RsaPrivateCrtKeyParameters privateKey, RSAKeyFormat keyFormat)

// Hex格式转换
string PublicKeyToHex(RsaKeyParameters publicKey, RSAKeyFormat keyFormat)
string PrivateKeyToHex(RsaPrivateCrtKeyParameters privateKey, RSAKeyFormat keyFormat)

// PKCS格式互转
string ConvertPkcs1ToPkcs8(string pkcs1Key, bool isPrivateKey, InputFormat inputFormat, OutputFormat outputFormat)
string ConvertPkcs8ToPkcs1(string pkcs8Key, bool isPrivateKey, InputFormat inputFormat, OutputFormat outputFormat)
```

#### 密钥解析
```csharp
// 从各种格式解析密钥
RsaKeyParameters ParsePublicKeyFromPem(string pemKey)
RsaKeyParameters ParsePublicKeyFromBase64(string base64Key, RSAKeyFormat keyFormat)
RsaKeyParameters ParsePublicKeyFromHex(string hexKey, RSAKeyFormat keyFormat)
RsaPrivateCrtKeyParameters ParsePrivateKeyFromPem(string pemKey)
RsaPrivateCrtKeyParameters ParsePrivateKeyFromBase64(string base64Key, RSAKeyFormat keyFormat)
RsaPrivateCrtKeyParameters ParsePrivateKeyFromHex(string hexKey, RSAKeyFormat keyFormat)
```

#### 加解密
```csharp
// 字符串加解密
string Encrypt(string plaintext, RsaKeyParameters publicKey, RSAPadding padding, OutputFormat outputFormat, Encoding encoding)
string Decrypt(string ciphertext, RsaPrivateCrtKeyParameters privateKey, RSAPadding padding, InputFormat inputFormat, Encoding encoding)

// 字节数组加解密
byte[] Encrypt(byte[] plaintext, RsaKeyParameters publicKey, RSAPadding padding)
byte[] Decrypt(byte[] ciphertext, RsaPrivateCrtKeyParameters privateKey, RSAPadding padding)
```

#### 签名验签
```csharp
// 字符串签名验签
string Sign(string data, RsaPrivateCrtKeyParameters privateKey, SignatureAlgorithm algorithm, OutputFormat outputFormat, Encoding encoding)
bool Verify(string data, string signature, RsaKeyParameters publicKey, SignatureAlgorithm algorithm, InputFormat inputFormat, Encoding encoding)

// 字节数组签名验签
byte[] Sign(byte[] data, RsaPrivateCrtKeyParameters privateKey, SignatureAlgorithm algorithm)
bool Verify(byte[] data, byte[] signature, RsaKeyParameters publicKey, SignatureAlgorithm algorithm)
```

#### 证书处理
```csharp
// 生成自签名证书
X509Certificate2 GenerateSelfSignedCertificate(AsymmetricCipherKeyPair keyPair, string subject, DateTime validFrom, DateTime validTo, SignatureAlgorithm algorithm)

// 从证书导出密钥
string ExportPublicKeyFromCertificate(X509Certificate2 certificate, OutputFormat format, RSAKeyFormat keyFormat)
string ExportPrivateKeyFromCertificate(X509Certificate2 certificate, OutputFormat format, RSAKeyFormat keyFormat)

// 导出证书
string ExportCertificateToPem(X509Certificate2 certificate)
```

## 使用示例

### 基本密钥生成和加解密
```csharp
// 生成2048位密钥对
var keyPair = RSAUtil.GenerateKeyPair(2048);
var publicKey = (RsaKeyParameters)keyPair.Public;
var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

// 加密
string plaintext = "Hello RSA!";
string encrypted = RSAUtil.Encrypt(plaintext, publicKey);

// 解密
string decrypted = RSAUtil.Decrypt(encrypted, privateKey);
```

### 签名验签示例
```csharp
string data = "需要签名的数据";

// 签名
string signature = RSAUtil.Sign(data, privateKey, RSAUtil.SignatureAlgorithm.SHA256withRSA);

// 验签
bool isValid = RSAUtil.Verify(data, signature, publicKey, RSAUtil.SignatureAlgorithm.SHA256withRSA);
```

### 密钥格式转换示例
```csharp
// 生成PEM格式密钥
string pemPublicKey = RSAUtil.GeneratePublicKeyString(publicKey, RSAUtil.OutputFormat.PEM, RSAUtil.RSAKeyFormat.PKCS1);

// 转换为PKCS8格式
string pkcs8PublicKey = RSAUtil.ConvertPkcs1ToPkcs8(pemPublicKey, false);
```

### 证书生成示例
```csharp
// 生成自签名证书
var certificate = RSAUtil.GenerateSelfSignedCertificate(
    keyPair, 
    "CN=Test Certificate, O=Test Organization, C=CN",
    DateTime.Now,
    DateTime.Now.AddYears(1)
);

// 导出证书PEM格式
string certPem = RSAUtil.ExportCertificateToPem(certificate);
```

## 兼容性

### .NET Standard 2.1 支持
- 完全兼容 `.NET Standard 2.1` 框架
- 使用 BouncyCastle 加密库提供跨平台支持
- 支持现代 .NET 应用程序

### 向后兼容
- 保留了原有的接口方法以确保现有代码的兼容性
- 支持旧版本的 `RSAType` 枚举（RSA/RSA2）
- 提供了兼容的 `CreateRSAKey`、`EncryptByRSA`、`DecryptByRSA` 等方法

## 安全建议

1. **密钥长度**：推荐使用2048位或更高长度的密钥
2. **签名算法**：推荐使用SHA256withRSA或更高强度的算法
3. **填充方式**：对于新应用推荐使用OAEP填充，提供更高的安全性
4. **密钥管理**：私钥应该安全存储，避免硬编码在代码中
5. **证书验证**：在生产环境中使用证书时应该进行完整的证书链验证

## 测试覆盖

实现了完整的测试用例，包括：
- 基础功能测试
- 密钥格式转换测试
- 加解密功能测试
- 签名验签测试
- 证书处理测试
- 多格式支持测试
- 字符集兼容性测试
- .NET Standard 2.1兼容性测试

所有测试用例都包含在 `Program.cs` 的 `RSATest()` 方法中，可以通过运行控制台应用程序进行验证。

## 总结

本RSA工具类实现了完整的RSA加密功能，支持现代密码学最佳实践，同时保持向后兼容性，适用于各种.NET应用场景。