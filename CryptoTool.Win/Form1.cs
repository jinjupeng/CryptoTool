using CryptoTool.Common;
using CryptoTool.Common.GM;
using System.Text;

namespace CryptoTool.Win
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            // 初始化默认值
            comboRSAKeySize.SelectedIndex = 1; // 2048
            comboRSAKeyFormat.SelectedIndex = 0; // XML
            comboRSAType.SelectedIndex = 1; // RSA2
            comboSM4Mode.SelectedIndex = 0; // ECB
            comboSM4Padding.SelectedIndex = 0; // PKCS7
            
            SetStatus("就绪");
        }

        #region RSA功能

        private void btnGenerateRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成RSA密钥对...");
                
                int keySize = int.Parse(comboRSAKeySize.SelectedItem.ToString());
                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);
                
                var keyPair = RSAUtil.CreateRSAKey(keySize, format);
                
                textRSAPublicKey.Text = keyPair.Key;
                textRSAPrivateKey.Text = keyPair.Value;
                
                SetStatus($"RSA密钥对生成完成 - {keySize}位 {formatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成RSA密钥对失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成RSA密钥对失败");
            }
        }

        private void btnRSAEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSAPlainText.Text))
                {
                    MessageBox.Show("请输入明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPublicKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA加密...");

                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string cipherText = RSAUtil.EncryptByRSA(textRSAPlainText.Text, textRSAPublicKey.Text, format);
                textRSACipherText.Text = cipherText;

                SetStatus("RSA加密完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA加密失败");
            }
        }

        private void btnRSADecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSACipherText.Text))
                {
                    MessageBox.Show("请输入密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA解密...");

                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string plainText = RSAUtil.DecryptByRSA(textRSACipherText.Text, textRSAPrivateKey.Text, format);
                textRSAPlainText.Text = plainText;

                SetStatus("RSA解密完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA解密失败");
            }
        }

        private void btnRSASign_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSASignData.Text))
                {
                    MessageBox.Show("请输入要签名的原文数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA私钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA签名...");

                string rsaTypeText = comboRSAType.SelectedItem.ToString();
                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                
                RSAUtil.RSAType rsaType = (RSAUtil.RSAType)Enum.Parse(typeof(RSAUtil.RSAType), rsaTypeText);
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string signature = RSAUtil.HashAndSignString(textRSASignData.Text, textRSAPrivateKey.Text, rsaType, format);
                textRSASignature.Text = signature;

                SetStatus($"RSA签名完成 - 使用{rsaTypeText}算法");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA签名失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA签名失败");
            }
        }

        private void btnRSAVerify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSASignData.Text))
                {
                    MessageBox.Show("请输入原文数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSASignature.Text))
                {
                    MessageBox.Show("请输入签名数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPublicKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA公钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行RSA验签...");

                string rsaTypeText = comboRSAType.SelectedItem.ToString();
                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                
                RSAUtil.RSAType rsaType = (RSAUtil.RSAType)Enum.Parse(typeof(RSAUtil.RSAType), rsaTypeText);
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                bool verifyResult = RSAUtil.VerifySigned(textRSASignData.Text, textRSASignature.Text, textRSAPublicKey.Text, rsaType, format);
                
                labelRSAVerifyResult.Text = $"验签结果: {(verifyResult ? "验证成功" : "验证失败")}";
                labelRSAVerifyResult.ForeColor = verifyResult ? Color.Green : Color.Red;

                SetStatus($"RSA验签完成 - {(verifyResult ? "验证成功" : "验证失败")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA验签失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelRSAVerifyResult.Text = "验签结果: 验证异常";
                labelRSAVerifyResult.ForeColor = Color.Red;
                SetStatus("RSA验签失败");
            }
        }

        #endregion

        #region SM4功能

        private void btnGenerateSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成SM4密钥...");
                string key = SM4Util.GenerateKey();
                textSM4Key.Text = key;
                SetStatus("SM4密钥生成完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成SM4密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成SM4密钥失败");
            }
        }

        private void btnGenerateSM4IV_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成SM4初始向量...");
                string iv = SM4Util.GenerateIV();
                textSM4IV.Text = iv;
                SetStatus("SM4初始向量生成完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成SM4初始向量失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成SM4初始向量失败");
            }
        }

        private void btnSM4Encrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4PlainText.Text))
                {
                    MessageBox.Show("请输入明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("请先生成或输入SM4密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboSM4Mode.SelectedItem.ToString();
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBC模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM4加密...");

                string paddingText = comboSM4Padding.SelectedItem.ToString();
                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);

                // 将Base64密钥转换为字符串密钥（用于传递给SM4Util的字符串方法）
                byte[] keyBytes = Convert.FromBase64String(textSM4Key.Text);
                string keyString = Encoding.UTF8.GetString(keyBytes);

                string cipherText;
                if (mode == "ECB")
                {
                    cipherText = SM4Util.EncryptEcb(textSM4PlainText.Text, keyString, Encoding.UTF8, padding);
                }
                else // CBC
                {
                    byte[] ivBytes = Convert.FromBase64String(textSM4IV.Text);
                    string ivString = Encoding.UTF8.GetString(ivBytes);
                    cipherText = SM4Util.EncryptCbc(textSM4PlainText.Text, keyString, ivString, Encoding.UTF8, padding);
                }

                textSM4CipherText.Text = cipherText;
                SetStatus($"SM4加密完成 - 使用{mode}模式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM4加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM4加密失败");
            }
        }

        private void btnSM4Decrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4CipherText.Text))
                {
                    MessageBox.Show("请输入密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("请先生成或输入SM4密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboSM4Mode.SelectedItem.ToString();
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBC模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM4解密...");

                string paddingText = comboSM4Padding.SelectedItem.ToString();
                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);

                // 将Base64密钥转换为字符串密钥
                byte[] keyBytes = Convert.FromBase64String(textSM4Key.Text);
                string keyString = Encoding.UTF8.GetString(keyBytes);

                string plainText;
                if (mode == "ECB")
                {
                    plainText = SM4Util.DecryptEcb(textSM4CipherText.Text, keyString, Encoding.UTF8, padding);
                }
                else // CBC
                {
                    byte[] ivBytes = Convert.FromBase64String(textSM4IV.Text);
                    string ivString = Encoding.UTF8.GetString(ivBytes);
                    plainText = SM4Util.DecryptCbc(textSM4CipherText.Text, keyString, ivString, Encoding.UTF8, padding);
                }

                textSM4PlainText.Text = plainText;
                SetStatus($"SM4解密完成 - 使用{mode}模式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM4解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM4解密失败");
            }
        }

        private void comboSM4Mode_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 当选择ECB模式时，禁用初始向量相关控件
            bool isCBC = comboSM4Mode.SelectedItem.ToString() == "CBC";
            textSM4IV.Enabled = isCBC;
            btnGenerateSM4IV.Enabled = isCBC;
            
            if (!isCBC)
            {
                textSM4IV.Text = "";
            }
        }

        #endregion

        #region 辅助方法

        private void SetStatus(string message)
        {
            toolStripStatusLabel1.Text = message;
            Application.DoEvents();
        }

        #endregion
    }
}
