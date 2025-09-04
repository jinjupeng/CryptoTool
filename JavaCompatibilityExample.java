import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.Base64;

/**
 * Java端SM2工具类，用于与C#端进行兼容性测试
 * 重点解决密文格式兼容性问题
 */
public class JavaCompatibilityExample {
    private static final String CURVE_NAME = "sm2p256v1";
    private static final int RS_LENGTH = 32;
    private static final int C1_LENGTH = 65; // 未压缩点长度（包含0x04前缀）
    private static final int C1_LENGTH_NO_PREFIX = 64; // 不包含0x04前缀的长度
    private static final int C3_LENGTH = 32;
    
    // SM2曲线参数
    private static final X9ECParameters SM2_ECX9_PARAMS = GMNamedCurves.getByName(CURVE_NAME);
    private static final ECDomainParameters SM2_DOMAIN_PARAMS = new ECDomainParameters(
        SM2_ECX9_PARAMS.getCurve(),
        SM2_ECX9_PARAMS.getG(),
        SM2_ECX9_PARAMS.getN(),
        SM2_ECX9_PARAMS.getH()
    );

    /**
     * 从16进制字符串创建公钥
     */
    public static ECPublicKeyParameters createPublicKeyFromHex(String hexPublicKey) {
        byte[] keyBytes = Hex.decode(hexPublicKey);
        ECPoint point = SM2_ECX9_PARAMS.getCurve().decodePoint(keyBytes);
        return new ECPublicKeyParameters(point, SM2_DOMAIN_PARAMS);
    }

    /**
     * 从16进制字符串创建私钥
     */
    public static ECPrivateKeyParameters createPrivateKeyFromHex(String hexPrivateKey) {
        BigInteger d = new BigInteger(hexPrivateKey, 16);
        return new ECPrivateKeyParameters(d, SM2_DOMAIN_PARAMS);
    }

    /**
     * Java BouncyCastle加密（生成C#兼容的密文）
     * Java生成的密文需要在开头添加0x04才能被C#解密
     */
    public static String encryptForDotNet(String plainText, ECPublicKeyParameters publicKey) throws Exception {
        SM2Engine engine = new SM2Engine();
        engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
        
        byte[] plainBytes = plainText.getBytes("UTF-8");
        byte[] javaCiphertext = engine.processBlock(plainBytes, 0, plainBytes.length);
        
        // Java BouncyCastle生成的密文需要添加0x04前缀才能在C#中解密
        byte[] dotNetCompatibleCiphertext = addPrefixForDotNet(javaCiphertext);
        
        return Base64.toBase64String(dotNetCompatibleCiphertext);
    }

    /**
     * Java BouncyCastle解密（解密来自C#的密文）
     * 来自C#的密文需要移除开头的0x04才能被Java解密
     */
    public static String decryptFromDotNet(String encryptedData, ECPrivateKeyParameters privateKey) throws Exception {
        byte[] dotNetCiphertext = Base64.decode(encryptedData);
        
        // 来自C#的密文需要移除0x04前缀才能在Java中解密
        byte[] javaCompatibleCiphertext = removePrefixFromDotNet(dotNetCiphertext);
        
        SM2Engine engine = new SM2Engine();
        engine.init(false, privateKey);
        
        byte[] decryptedBytes = engine.processBlock(javaCompatibleCiphertext, 0, javaCompatibleCiphertext.length);
        return new String(decryptedBytes, "UTF-8");
    }

    /**
     * 为Java密文添加0x04前缀，使其与C# BouncyCastle兼容
     */
    private static byte[] addPrefixForDotNet(byte[] javaCiphertext) {
        if (javaCiphertext == null || javaCiphertext.length <= C1_LENGTH_NO_PREFIX + C3_LENGTH) {
            throw new IllegalArgumentException("无效的Java密文格式");
        }

        // Java BouncyCastle生成的密文格式：C1(64字节，不含0x04) + C2 + C3
        // C# BouncyCastle期望的格式：C1(65字节，含0x04) + C2 + C3
        byte[] dotNetCiphertext = new byte[javaCiphertext.length + 1];
        dotNetCiphertext[0] = 0x04; // 添加未压缩点标识
        System.arraycopy(javaCiphertext, 0, dotNetCiphertext, 1, javaCiphertext.length);
        
        return dotNetCiphertext;
    }

    /**
     * 从C#密文移除0x04前缀，使其与Java BouncyCastle兼容
     */
    private static byte[] removePrefixFromDotNet(byte[] dotNetCiphertext) {
        if (dotNetCiphertext == null || dotNetCiphertext.length <= C1_LENGTH + C3_LENGTH) {
            throw new IllegalArgumentException("无效的C#密文格式");
        }

        if (dotNetCiphertext[0] != 0x04) {
            throw new IllegalArgumentException("C#密文格式错误：期望以0x04开头");
        }

        // C# BouncyCastle生成的密文格式：C1(65字节，含0x04) + C2 + C3
        // Java BouncyCastle期望的格式：C1(64字节，不含0x04) + C2 + C3
        byte[] javaCiphertext = new byte[dotNetCiphertext.length - 1];
        System.arraycopy(dotNetCiphertext, 1, javaCiphertext, 0, dotNetCiphertext.length - 1);
        
        return javaCiphertext;
    }

    /**
     * 检测密文是否为C#格式（包含0x04前缀）
     */
    public static boolean isDotNetFormat(byte[] ciphertext) {
        return ciphertext != null && 
               ciphertext.length > C1_LENGTH + C3_LENGTH && 
               ciphertext[0] == 0x04;
    }

    /**
     * 智能解密 - 自动检测密文来源并使用相应的解密方式
     */
    public static String smartDecrypt(String encryptedData, ECPrivateKeyParameters privateKey) throws Exception {
        byte[] ciphertext = Base64.decode(encryptedData);
        
        if (isDotNetFormat(ciphertext)) {
            System.out.println("检测到C#格式密文，使用C#兼容解密模式");
            return decryptFromDotNet(encryptedData, privateKey);
        } else {
            System.out.println("检测到Java格式密文，使用标准解密模式");
            // 标准Java解密
            SM2Engine engine = new SM2Engine();
            engine.init(false, privateKey);
            byte[] decryptedBytes = engine.processBlock(ciphertext, 0, ciphertext.length);
            return new String(decryptedBytes, "UTF-8");
        }
    }

    /**
     * 将ASN.1 DER格式签名转换为RS格式
     */
    public static byte[] convertAsn1ToRs(byte[] asn1Signature) throws Exception {
        ASN1Sequence sequence = ASN1Sequence.getInstance(asn1Signature);
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("ASN.1签名格式错误");
        }
        
        BigInteger r = ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();
        
        byte[] rBytes = bigIntegerToFixedBytes(r);
        byte[] sBytes = bigIntegerToFixedBytes(s);
        
        byte[] result = new byte[RS_LENGTH * 2];
        System.arraycopy(rBytes, 0, result, 0, RS_LENGTH);
        System.arraycopy(sBytes, 0, result, RS_LENGTH, RS_LENGTH);
        
        return result;
    }

    /**
     * 将RS格式签名转换为ASN.1 DER格式
     */
    public static byte[] convertRsToAsn1(byte[] rsSignature) throws Exception {
        if (rsSignature.length != RS_LENGTH * 2) {
            throw new IllegalArgumentException("RS签名长度错误");
        }
        
        byte[] rBytes = Arrays.copyOfRange(rsSignature, 0, RS_LENGTH);
        byte[] sBytes = Arrays.copyOfRange(rsSignature, RS_LENGTH, RS_LENGTH * 2);
        
        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);
        
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));
        
        return new DERSequence(vector).getEncoded("DER");
    }

    /**
     * 将BigInteger转换为固定长度字节数组（32字节）
     */
    private static byte[] bigIntegerToFixedBytes(BigInteger bigInt) {
        byte[] bytes = bigInt.toByteArray();
        
        if (bytes.length == RS_LENGTH) {
            return bytes;
        } else if (bytes.length == RS_LENGTH + 1 && bytes[0] == 0) {
            // 移除符号位
            return Arrays.copyOfRange(bytes, 1, RS_LENGTH + 1);
        } else if (bytes.length < RS_LENGTH) {
            // 前面补0
            byte[] result = new byte[RS_LENGTH];
            System.arraycopy(bytes, 0, result, RS_LENGTH - bytes.length, bytes.length);
            return result;
        } else {
            throw new IllegalArgumentException("BigInteger长度超出预期: " + bytes.length);
        }
    }

    /**
     * SM2签名（输出ASN.1格式）
     */
    public static String signSM2Asn1(byte[] data, ECPrivateKeyParameters privateKey) throws Exception {
        SM2Signer signer = new SM2Signer();
        signer.init(true, privateKey);
        signer.update(data, 0, data.length);
        byte[] signature = signer.generateSignature();
        return Hex.toHexString(signature).toUpperCase();
    }

    /**
     * SM2签名（输出RS格式）
     */
    public static String signSM2Rs(byte[] data, ECPrivateKeyParameters privateKey) throws Exception {
        // 先生成ASN.1格式签名
        String asn1Hex = signSM2Asn1(data, privateKey);
        byte[] asn1Bytes = Hex.decode(asn1Hex);
        
        // 转换为RS格式
        byte[] rsBytes = convertAsn1ToRs(asn1Bytes);
        return Hex.toHexString(rsBytes).toUpperCase();
    }

    /**
     * SM2验签
     */
    public static boolean verifySM2(byte[] data, String signatureHex, ECPublicKeyParameters publicKey, boolean isRsFormat) throws Exception {
        byte[] signatureBytes;
        
        if (isRsFormat) {
            // RS格式需要转换为ASN.1格式
            byte[] rsBytes = Hex.decode(signatureHex);
            signatureBytes = convertRsToAsn1(rsBytes);
        } else {
            // ASN.1格式直接使用
            signatureBytes = Hex.decode(signatureHex);
        }
        
        SM2Signer signer = new SM2Signer();
        signer.init(false, publicKey);
        signer.update(data, 0, data.length);
        return signer.verifySignature(signatureBytes);
    }

    /**
     * 测试方法
     */
    public static void main(String[] args) {
        try {
            System.out.println("=== Java端SM2兼容性测试 ===");
            
            // 使用固定的测试密钥（请替换为C#端生成的密钥）
            String hexPublicKey = "04FD1B00C159476108D81A649EEF2C03BF09E63CCA59F8FC26C5D8FE58D904CF9ABB135FA08A7293ECE5E164663CCC26DD77FEF19C17779362460D269F36B3CCEC";
            String hexPrivateKey = "0AF453D26831E0A71CD8D1C2F36A3E3A52B8B30C69FC1944EAF7B216C254C5EA";
            
            ECPublicKeyParameters publicKey = createPublicKeyFromHex(hexPublicKey);
            ECPrivateKeyParameters privateKey = createPrivateKeyFromHex(hexPrivateKey);
            
            // 测试数据
            String testData = "国密SM2非对称加密算法测试";
            byte[] dataBytes = testData.getBytes("UTF-8");
            
            System.out.println("测试数据: " + testData);
            System.out.println("公钥: " + hexPublicKey);
            System.out.println("私钥: " + hexPrivateKey);
            
            // === 加解密兼容性测试 ===
            System.out.println("\n=== 加解密兼容性测试 ===");
            
            // 1. Java加密，生成C#兼容密文
            String ciphertextForDotNet = encryptForDotNet(testData, publicKey);
            System.out.println("Java生成的C#兼容密文: " + ciphertextForDotNet);
            
            // 2. Java解密自己生成的C#兼容密文
            String decryptedFromOwn = decryptFromDotNet(ciphertextForDotNet, privateKey);
            System.out.println("Java解密自己的C#兼容密文: " + decryptedFromOwn);
            System.out.println("自解密验证: " + (testData.equals(decryptedFromOwn) ? "成功" : "失败"));
            
            // 3. 测试智能解密
            String smartDecryptResult = smartDecrypt(ciphertextForDotNet, privateKey);
            System.out.println("智能解密结果: " + smartDecryptResult);
            System.out.println("智能解密验证: " + (testData.equals(smartDecryptResult) ? "成功" : "失败"));
            
            // 4. 密文格式检测
            byte[] ciphertextBytes = Base64.decode(ciphertextForDotNet);
            boolean formatDetection = isDotNetFormat(ciphertextBytes);
            System.out.println("密文格式检测: " + (formatDetection ? "C#格式" : "Java格式"));
            
            // === 签名验签测试 ===
            System.out.println("\n=== 签名验签测试 ===");
            
            // 1. 生成ASN.1格式签名
            String asn1Signature = signSM2Asn1(dataBytes, privateKey);
            System.out.println("ASN.1格式签名: " + asn1Signature);
            
            // 2. 生成RS格式签名
            String rsSignature = signSM2Rs(dataBytes, privateKey);
            System.out.println("RS格式签名: " + rsSignature);
            
            // 3. 验证ASN.1格式签名
            boolean asn1Valid = verifySM2(dataBytes, asn1Signature, publicKey, false);
            System.out.println("ASN.1签名验证: " + (asn1Valid ? "成功" : "失败"));
            
            // 4. 验证RS格式签名
            boolean rsValid = verifySM2(dataBytes, rsSignature, publicKey, true);
            System.out.println("RS签名验证: " + (rsValid ? "成功" : "失败"));
            
            // 5. 格式转换测试
            byte[] asn1Bytes = Hex.decode(asn1Signature);
            byte[] rsBytes = Hex.decode(rsSignature);
            
            byte[] convertedRs = convertAsn1ToRs(asn1Bytes);
            byte[] convertedAsn1 = convertRsToAsn1(rsBytes);
            
            boolean rsConvertOk = Arrays.equals(rsBytes, convertedRs);
            boolean asn1ConvertOk = Arrays.equals(asn1Bytes, convertedAsn1);
            
            System.out.println("格式转换验证:");
            System.out.println("ASN.1 -> RS: " + (rsConvertOk ? "成功" : "失败"));
            System.out.println("RS -> ASN.1: " + (asn1ConvertOk ? "成功" : "失败"));
            
            System.out.println("\n=== 与C#端互转说明 ===");
            System.out.println("1. 加密兼容性：");
            System.out.println("   - Java端使用 encryptForDotNet() 生成C#兼容密文");
            System.out.println("   - Java端使用 decryptFromDotNet() 解密C#密文");
            System.out.println("   - C#端使用 EncryptForJava() 生成Java兼容密文");
            System.out.println("   - C#端使用 DecryptFromJava() 解密Java密文");
            System.out.println("2. 核心差异：C1部分的0x04前缀处理");
            System.out.println("   - Java密文：C1不含0x04前缀(64字节) + C2 + C3");
            System.out.println("   - C#密文：C1含0x04前缀(65字节) + C2 + C3");
            System.out.println("3. 智能解密：自动检测密文格式并选择合适的解密方式");
            System.out.println("4. 签名格式：两端完全兼容，支持ASN.1和RS格式互转");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}