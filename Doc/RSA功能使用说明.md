# RSA工具类功能使用说明

## 概述

优化后的RSAUtil类提供了完整的RSA加密、解密、签名、验签功能，支持RSA和RSA2算法，支持Java和C#互操作，以及多种密钥格式之间的转换。

## 主要功能

### 1. RSA/RSA2加密解密

#### 基本用法
```csharp
// 生成密钥对
var keyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.XML);
string publicKey = keyPair.Key;
string privateKey = keyPair.Value;

// 加密
string plaintext = "需要加密的内容";
string encrypted = RSAUtil.EncryptByRSA(plaintext, publicKey, RSAUtil.RSAKeyFormat.XML, RSAUtil.RSAPaddingMode.PKCS1);

// 解密
string decrypted = RSAUtil.DecryptByRSA(encrypted, privateKey, RSAUtil.RSAKeyFormat.XML, RSAUtil.RSAPaddingMode.PKCS1);
```

#### 支持的填充模式
- `RSAPaddingMode.PKCS1`: PKCS#1 v1.5填充（默认）
- `RSAPaddingMode.OAEP`: OAEP填充

### 2. RSA/RSA2数字签名

#### RSA签名（SHA1）
```csharp
string plaintext = "需要签名的内容";
string signature = RSAUtil.HashAndSignString(plaintext, privateKey, RSAUtil.RSAType.RSA, RSAUtil.RSAKeyFormat.XML);
bool isValid = RSAUtil.VerifySigned(plaintext, signature, publicKey, RSAUtil.RSAType.RSA, RSAUtil.RSAKeyFormat.XML);
```

#### RSA2签名（SHA256）
```csharp
string plaintext = "需要签名的内容";
string signature = RSAUtil.HashAndSignString(plaintext, privateKey, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.XML);
bool isValid = RSAUtil.VerifySigned(plaintext, signature, publicKey, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.XML);
```

### 3. 多种密钥格式支持

#### 支持的密钥格式
- `RSAKeyFormat.XML`: C# XML格式（默认）
- `RSAKeyFormat.PKCS1`: PKCS#1格式（PEM编码）
- `RSAKeyFormat.PKCS8`: PKCS#8格式（PEM编码）
- `RSAKeyFormat.Java`: Java格式（Base64编码）

#### 生成不同格式的密钥
```csharp
// XML格式
var xmlKeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.XML);

// PKCS1格式
var pkcs1KeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.PKCS1);

// PKCS8格式
var pkcs8KeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.PKCS8);

// Java格式
var javaKeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.Java);
```

### 4. PKCS1和PKCS8格式转换

```csharp
// PKCS1转PKCS8
string pkcs8PublicKey = RSAUtil.ConvertPkcs1ToPkcs8(pkcs1PublicKey, false);
string pkcs8PrivateKey = RSAUtil.ConvertPkcs1ToPkcs8(pkcs1PrivateKey, true);

// PKCS8转PKCS1
string pkcs1PublicKey = RSAUtil.ConvertPkcs8ToPkcs1(pkcs8PublicKey, false);
string pkcs1PrivateKey = RSAUtil.ConvertPkcs8ToPkcs1(pkcs8PrivateKey, true);
```

### 5. Java互操作性

#### C#与Java格式转换
```csharp
// C# XML格式转Java格式
string javaPublicKey = RSAUtil.ConvertToJavaFormat(xmlPublicKey, false);
string javaPrivateKey = RSAUtil.ConvertToJavaFormat(xmlPrivateKey, true);

// Java格式转C# XML格式
string xmlPublicKey = RSAUtil.ConvertFromJavaFormat(javaPublicKey, false);
string xmlPrivateKey = RSAUtil.ConvertFromJavaFormat(javaPrivateKey, true);
```

#### Java兼容的加密解密
```csharp
// 使用Java格式密钥进行加密解密
string encrypted = RSAUtil.EncryptForJava(plaintext, javaPublicKey);
string decrypted = RSAUtil.DecryptFromJava(encrypted, javaPrivateKey);
```

#### Java兼容的签名验签
```csharp
// 使用Java格式密钥进行签名验签
string signature = RSAUtil.SignForJava(plaintext, javaPrivateKey, RSAUtil.RSAType.RSA2);
bool isValid = RSAUtil.VerifyFromJava(plaintext, signature, javaPublicKey, RSAUtil.RSAType.RSA2);
```

### 6. 向后兼容

原有的方法签名保持不变，确保向后兼容：

```csharp
// 原有方法仍然可用
var keyPair = RSAUtil.CreateRSAKey();
string encrypted = RSAUtil.EncryptByRSA(plaintext, keyPair.Key);
string decrypted = RSAUtil.DecryptByRSA(encrypted, keyPair.Value);
string signature = RSAUtil.HashAndSignString(plaintext, keyPair.Value);
bool isValid = RSAUtil.VerifySigned(plaintext, signature, keyPair.Key);
```

## 实际应用场景

### 1. 与支付宝API对接
```csharp
// 生成支付宝格式的密钥对（PKCS8）
var keyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.PKCS8);

// 使用RSA2进行签名
string signature = RSAUtil.HashAndSignString(signContent, privateKey, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.PKCS8);

// 验证支付宝返回的签名
bool isValid = RSAUtil.VerifySigned(responseContent, aliPaySignature, aliPayPublicKey, RSAUtil.RSAType.RSA2, RSAUtil.RSAKeyFormat.PKCS8);
```

### 2. 与Java系统对接
```csharp
// 生成Java兼容的密钥对
var javaKeyPair = RSAUtil.CreateRSAKey(2048, RSAUtil.RSAKeyFormat.Java);

// Java兼容的加密（Java端可以用对应私钥解密）
string encrypted = RSAUtil.EncryptForJava(plaintext, javaPublicKey);

// Java兼容的签名（Java端可以用对应公钥验证）
string signature = RSAUtil.SignForJava(plaintext, javaPrivateKey, RSAUtil.RSAType.RSA2);
```

### 3. 密钥格式转换
```csharp
// 将现有的PKCS1格式密钥转换为PKCS8格式
string pkcs8PrivateKey = RSAUtil.ConvertPkcs1ToPkcs8(pkcs1PrivateKey, true);

// 将Java格式密钥转换为C# XML格式
string xmlPublicKey = RSAUtil.ConvertFromJavaFormat(javaPublicKey, false);
```

## 注意事项

1. **密钥长度**: 建议使用2048位或以上的密钥长度以确保安全性
2. **算法选择**: RSA2（SHA256）比RSA（SHA1）更安全，建议优先使用RSA2
3. **填充模式**: PKCS1填充兼容性更好，OAEP填充安全性更高
4. **密钥格式**: 根据对接系统选择合适的密钥格式
5. **编码格式**: 加密结果和签名结果均为Base64编码字符串

## 错误处理

所有方法都会在参数无效或操作失败时抛出相应的异常，建议在调用时添加适当的异常处理：

```csharp
try
{
    string encrypted = RSAUtil.EncryptByRSA(plaintext, publicKey, RSAUtil.RSAKeyFormat.XML);
}
catch (ArgumentException ex)
{
    // 参数错误处理
    Console.WriteLine($"参数错误: {ex.Message}");
}
catch (CryptographicException ex)
{
    // 加密操作错误处理
    Console.WriteLine($"加密错误: {ex.Message}");
}
```