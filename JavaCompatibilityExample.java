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
 * Java��SM2�����࣬������C#�˽��м����Բ���
 * �ص������ĸ�ʽ����������
 */
public class JavaCompatibilityExample {
    private static final String CURVE_NAME = "sm2p256v1";
    private static final int RS_LENGTH = 32;
    private static final int C1_LENGTH = 65; // δѹ���㳤�ȣ�����0x04ǰ׺��
    private static final int C1_LENGTH_NO_PREFIX = 64; // ������0x04ǰ׺�ĳ���
    private static final int C3_LENGTH = 32;
    
    // SM2���߲���
    private static final X9ECParameters SM2_ECX9_PARAMS = GMNamedCurves.getByName(CURVE_NAME);
    private static final ECDomainParameters SM2_DOMAIN_PARAMS = new ECDomainParameters(
        SM2_ECX9_PARAMS.getCurve(),
        SM2_ECX9_PARAMS.getG(),
        SM2_ECX9_PARAMS.getN(),
        SM2_ECX9_PARAMS.getH()
    );

    /**
     * ��16�����ַ���������Կ
     */
    public static ECPublicKeyParameters createPublicKeyFromHex(String hexPublicKey) {
        byte[] keyBytes = Hex.decode(hexPublicKey);
        ECPoint point = SM2_ECX9_PARAMS.getCurve().decodePoint(keyBytes);
        return new ECPublicKeyParameters(point, SM2_DOMAIN_PARAMS);
    }

    /**
     * ��16�����ַ�������˽Կ
     */
    public static ECPrivateKeyParameters createPrivateKeyFromHex(String hexPrivateKey) {
        BigInteger d = new BigInteger(hexPrivateKey, 16);
        return new ECPrivateKeyParameters(d, SM2_DOMAIN_PARAMS);
    }

    /**
     * Java BouncyCastle���ܣ�����C#���ݵ����ģ�
     * Java���ɵ�������Ҫ�ڿ�ͷ���0x04���ܱ�C#����
     */
    public static String encryptForDotNet(String plainText, ECPublicKeyParameters publicKey) throws Exception {
        SM2Engine engine = new SM2Engine();
        engine.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
        
        byte[] plainBytes = plainText.getBytes("UTF-8");
        byte[] javaCiphertext = engine.processBlock(plainBytes, 0, plainBytes.length);
        
        // Java BouncyCastle���ɵ�������Ҫ���0x04ǰ׺������C#�н���
        byte[] dotNetCompatibleCiphertext = addPrefixForDotNet(javaCiphertext);
        
        return Base64.toBase64String(dotNetCompatibleCiphertext);
    }

    /**
     * Java BouncyCastle���ܣ���������C#�����ģ�
     * ����C#��������Ҫ�Ƴ���ͷ��0x04���ܱ�Java����
     */
    public static String decryptFromDotNet(String encryptedData, ECPrivateKeyParameters privateKey) throws Exception {
        byte[] dotNetCiphertext = Base64.decode(encryptedData);
        
        // ����C#��������Ҫ�Ƴ�0x04ǰ׺������Java�н���
        byte[] javaCompatibleCiphertext = removePrefixFromDotNet(dotNetCiphertext);
        
        SM2Engine engine = new SM2Engine();
        engine.init(false, privateKey);
        
        byte[] decryptedBytes = engine.processBlock(javaCompatibleCiphertext, 0, javaCompatibleCiphertext.length);
        return new String(decryptedBytes, "UTF-8");
    }

    /**
     * ΪJava�������0x04ǰ׺��ʹ����C# BouncyCastle����
     */
    private static byte[] addPrefixForDotNet(byte[] javaCiphertext) {
        if (javaCiphertext == null || javaCiphertext.length <= C1_LENGTH_NO_PREFIX + C3_LENGTH) {
            throw new IllegalArgumentException("��Ч��Java���ĸ�ʽ");
        }

        // Java BouncyCastle���ɵ����ĸ�ʽ��C1(64�ֽڣ�����0x04) + C2 + C3
        // C# BouncyCastle�����ĸ�ʽ��C1(65�ֽڣ���0x04) + C2 + C3
        byte[] dotNetCiphertext = new byte[javaCiphertext.length + 1];
        dotNetCiphertext[0] = 0x04; // ���δѹ�����ʶ
        System.arraycopy(javaCiphertext, 0, dotNetCiphertext, 1, javaCiphertext.length);
        
        return dotNetCiphertext;
    }

    /**
     * ��C#�����Ƴ�0x04ǰ׺��ʹ����Java BouncyCastle����
     */
    private static byte[] removePrefixFromDotNet(byte[] dotNetCiphertext) {
        if (dotNetCiphertext == null || dotNetCiphertext.length <= C1_LENGTH + C3_LENGTH) {
            throw new IllegalArgumentException("��Ч��C#���ĸ�ʽ");
        }

        if (dotNetCiphertext[0] != 0x04) {
            throw new IllegalArgumentException("C#���ĸ�ʽ����������0x04��ͷ");
        }

        // C# BouncyCastle���ɵ����ĸ�ʽ��C1(65�ֽڣ���0x04) + C2 + C3
        // Java BouncyCastle�����ĸ�ʽ��C1(64�ֽڣ�����0x04) + C2 + C3
        byte[] javaCiphertext = new byte[dotNetCiphertext.length - 1];
        System.arraycopy(dotNetCiphertext, 1, javaCiphertext, 0, dotNetCiphertext.length - 1);
        
        return javaCiphertext;
    }

    /**
     * ��������Ƿ�ΪC#��ʽ������0x04ǰ׺��
     */
    public static boolean isDotNetFormat(byte[] ciphertext) {
        return ciphertext != null && 
               ciphertext.length > C1_LENGTH + C3_LENGTH && 
               ciphertext[0] == 0x04;
    }

    /**
     * ���ܽ��� - �Զ����������Դ��ʹ����Ӧ�Ľ��ܷ�ʽ
     */
    public static String smartDecrypt(String encryptedData, ECPrivateKeyParameters privateKey) throws Exception {
        byte[] ciphertext = Base64.decode(encryptedData);
        
        if (isDotNetFormat(ciphertext)) {
            System.out.println("��⵽C#��ʽ���ģ�ʹ��C#���ݽ���ģʽ");
            return decryptFromDotNet(encryptedData, privateKey);
        } else {
            System.out.println("��⵽Java��ʽ���ģ�ʹ�ñ�׼����ģʽ");
            // ��׼Java����
            SM2Engine engine = new SM2Engine();
            engine.init(false, privateKey);
            byte[] decryptedBytes = engine.processBlock(ciphertext, 0, ciphertext.length);
            return new String(decryptedBytes, "UTF-8");
        }
    }

    /**
     * ��ASN.1 DER��ʽǩ��ת��ΪRS��ʽ
     */
    public static byte[] convertAsn1ToRs(byte[] asn1Signature) throws Exception {
        ASN1Sequence sequence = ASN1Sequence.getInstance(asn1Signature);
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("ASN.1ǩ����ʽ����");
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
     * ��RS��ʽǩ��ת��ΪASN.1 DER��ʽ
     */
    public static byte[] convertRsToAsn1(byte[] rsSignature) throws Exception {
        if (rsSignature.length != RS_LENGTH * 2) {
            throw new IllegalArgumentException("RSǩ�����ȴ���");
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
     * ��BigIntegerת��Ϊ�̶������ֽ����飨32�ֽڣ�
     */
    private static byte[] bigIntegerToFixedBytes(BigInteger bigInt) {
        byte[] bytes = bigInt.toByteArray();
        
        if (bytes.length == RS_LENGTH) {
            return bytes;
        } else if (bytes.length == RS_LENGTH + 1 && bytes[0] == 0) {
            // �Ƴ�����λ
            return Arrays.copyOfRange(bytes, 1, RS_LENGTH + 1);
        } else if (bytes.length < RS_LENGTH) {
            // ǰ�油0
            byte[] result = new byte[RS_LENGTH];
            System.arraycopy(bytes, 0, result, RS_LENGTH - bytes.length, bytes.length);
            return result;
        } else {
            throw new IllegalArgumentException("BigInteger���ȳ���Ԥ��: " + bytes.length);
        }
    }

    /**
     * SM2ǩ�������ASN.1��ʽ��
     */
    public static String signSM2Asn1(byte[] data, ECPrivateKeyParameters privateKey) throws Exception {
        SM2Signer signer = new SM2Signer();
        signer.init(true, privateKey);
        signer.update(data, 0, data.length);
        byte[] signature = signer.generateSignature();
        return Hex.toHexString(signature).toUpperCase();
    }

    /**
     * SM2ǩ�������RS��ʽ��
     */
    public static String signSM2Rs(byte[] data, ECPrivateKeyParameters privateKey) throws Exception {
        // ������ASN.1��ʽǩ��
        String asn1Hex = signSM2Asn1(data, privateKey);
        byte[] asn1Bytes = Hex.decode(asn1Hex);
        
        // ת��ΪRS��ʽ
        byte[] rsBytes = convertAsn1ToRs(asn1Bytes);
        return Hex.toHexString(rsBytes).toUpperCase();
    }

    /**
     * SM2��ǩ
     */
    public static boolean verifySM2(byte[] data, String signatureHex, ECPublicKeyParameters publicKey, boolean isRsFormat) throws Exception {
        byte[] signatureBytes;
        
        if (isRsFormat) {
            // RS��ʽ��Ҫת��ΪASN.1��ʽ
            byte[] rsBytes = Hex.decode(signatureHex);
            signatureBytes = convertRsToAsn1(rsBytes);
        } else {
            // ASN.1��ʽֱ��ʹ��
            signatureBytes = Hex.decode(signatureHex);
        }
        
        SM2Signer signer = new SM2Signer();
        signer.init(false, publicKey);
        signer.update(data, 0, data.length);
        return signer.verifySignature(signatureBytes);
    }

    /**
     * ���Է���
     */
    public static void main(String[] args) {
        try {
            System.out.println("=== Java��SM2�����Բ��� ===");
            
            // ʹ�ù̶��Ĳ�����Կ�����滻ΪC#�����ɵ���Կ��
            String hexPublicKey = "04FD1B00C159476108D81A649EEF2C03BF09E63CCA59F8FC26C5D8FE58D904CF9ABB135FA08A7293ECE5E164663CCC26DD77FEF19C17779362460D269F36B3CCEC";
            String hexPrivateKey = "0AF453D26831E0A71CD8D1C2F36A3E3A52B8B30C69FC1944EAF7B216C254C5EA";
            
            ECPublicKeyParameters publicKey = createPublicKeyFromHex(hexPublicKey);
            ECPrivateKeyParameters privateKey = createPrivateKeyFromHex(hexPrivateKey);
            
            // ��������
            String testData = "����SM2�ǶԳƼ����㷨����";
            byte[] dataBytes = testData.getBytes("UTF-8");
            
            System.out.println("��������: " + testData);
            System.out.println("��Կ: " + hexPublicKey);
            System.out.println("˽Կ: " + hexPrivateKey);
            
            // === �ӽ��ܼ����Բ��� ===
            System.out.println("\n=== �ӽ��ܼ����Բ��� ===");
            
            // 1. Java���ܣ�����C#��������
            String ciphertextForDotNet = encryptForDotNet(testData, publicKey);
            System.out.println("Java���ɵ�C#��������: " + ciphertextForDotNet);
            
            // 2. Java�����Լ����ɵ�C#��������
            String decryptedFromOwn = decryptFromDotNet(ciphertextForDotNet, privateKey);
            System.out.println("Java�����Լ���C#��������: " + decryptedFromOwn);
            System.out.println("�Խ�����֤: " + (testData.equals(decryptedFromOwn) ? "�ɹ�" : "ʧ��"));
            
            // 3. �������ܽ���
            String smartDecryptResult = smartDecrypt(ciphertextForDotNet, privateKey);
            System.out.println("���ܽ��ܽ��: " + smartDecryptResult);
            System.out.println("���ܽ�����֤: " + (testData.equals(smartDecryptResult) ? "�ɹ�" : "ʧ��"));
            
            // 4. ���ĸ�ʽ���
            byte[] ciphertextBytes = Base64.decode(ciphertextForDotNet);
            boolean formatDetection = isDotNetFormat(ciphertextBytes);
            System.out.println("���ĸ�ʽ���: " + (formatDetection ? "C#��ʽ" : "Java��ʽ"));
            
            // === ǩ����ǩ���� ===
            System.out.println("\n=== ǩ����ǩ���� ===");
            
            // 1. ����ASN.1��ʽǩ��
            String asn1Signature = signSM2Asn1(dataBytes, privateKey);
            System.out.println("ASN.1��ʽǩ��: " + asn1Signature);
            
            // 2. ����RS��ʽǩ��
            String rsSignature = signSM2Rs(dataBytes, privateKey);
            System.out.println("RS��ʽǩ��: " + rsSignature);
            
            // 3. ��֤ASN.1��ʽǩ��
            boolean asn1Valid = verifySM2(dataBytes, asn1Signature, publicKey, false);
            System.out.println("ASN.1ǩ����֤: " + (asn1Valid ? "�ɹ�" : "ʧ��"));
            
            // 4. ��֤RS��ʽǩ��
            boolean rsValid = verifySM2(dataBytes, rsSignature, publicKey, true);
            System.out.println("RSǩ����֤: " + (rsValid ? "�ɹ�" : "ʧ��"));
            
            // 5. ��ʽת������
            byte[] asn1Bytes = Hex.decode(asn1Signature);
            byte[] rsBytes = Hex.decode(rsSignature);
            
            byte[] convertedRs = convertAsn1ToRs(asn1Bytes);
            byte[] convertedAsn1 = convertRsToAsn1(rsBytes);
            
            boolean rsConvertOk = Arrays.equals(rsBytes, convertedRs);
            boolean asn1ConvertOk = Arrays.equals(asn1Bytes, convertedAsn1);
            
            System.out.println("��ʽת����֤:");
            System.out.println("ASN.1 -> RS: " + (rsConvertOk ? "�ɹ�" : "ʧ��"));
            System.out.println("RS -> ASN.1: " + (asn1ConvertOk ? "�ɹ�" : "ʧ��"));
            
            System.out.println("\n=== ��C#�˻�ת˵�� ===");
            System.out.println("1. ���ܼ����ԣ�");
            System.out.println("   - Java��ʹ�� encryptForDotNet() ����C#��������");
            System.out.println("   - Java��ʹ�� decryptFromDotNet() ����C#����");
            System.out.println("   - C#��ʹ�� EncryptForJava() ����Java��������");
            System.out.println("   - C#��ʹ�� DecryptFromJava() ����Java����");
            System.out.println("2. ���Ĳ��죺C1���ֵ�0x04ǰ׺����");
            System.out.println("   - Java���ģ�C1����0x04ǰ׺(64�ֽ�) + C2 + C3");
            System.out.println("   - C#���ģ�C1��0x04ǰ׺(65�ֽ�) + C2 + C3");
            System.out.println("3. ���ܽ��ܣ��Զ�������ĸ�ʽ��ѡ����ʵĽ��ܷ�ʽ");
            System.out.println("4. ǩ����ʽ��������ȫ���ݣ�֧��ASN.1��RS��ʽ��ת");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}