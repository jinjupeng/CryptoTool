using CryptoTool.Common;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoTool.Win
{
    public partial class RSATabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public RSATabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // 初始化默认值
            comboRSAKeySize.SelectedIndex = 1; // 2048
            comboRSAKeyFormat.SelectedIndex = 1; // pkcs#8
            comboRSAKeyPadding.SelectedIndex = 0; // PKCS1
            comboRSAKeyOutputFormat.SelectedIndex = 1; // base64
            comboRSAEncryptOutputFormat.SelectedIndex = 0; // base64
            comboRSASignAlgmFormat.SelectedIndex = 1; // SHA256withRSA(RSA2)
            comboRSASignOutputFormat.SelectedIndex = 0; // base64
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region RSA功能

        private void btnGenerateRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成RSA密钥对...");

                int keySize = int.Parse(comboRSAKeySize.SelectedItem.ToString());
                string formatText = comboRSAKeyFormat.SelectedIndex.ToString();
                string outputFormat = comboRSAKeyOutputFormat.SelectedIndex.ToString();
                RSAUtil.RSAKeyType rsaKeyFormat = (RSAUtil.RSAKeyType)Enum.Parse(typeof(RSAUtil.RSAKeyType), formatText);
                RSAUtil.RSAKeyFormat rsaOutputFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), outputFormat);

                var keyPair = RSAUtil.GenerateKeyPair(keySize);
                var publicKey = (RsaKeyParameters)keyPair.Public;
                var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
                string genPublicKey = RSAUtil.GeneratePublicKeyString(publicKey, rsaOutputFormat, rsaKeyFormat);
                string genPrivateKey = RSAUtil.GeneratePrivateKeyString(privateKey, rsaOutputFormat, rsaKeyFormat);

                textRSAPublicKey.Text = genPublicKey;
                textRSAPrivateKey.Text = genPrivateKey;

                SetStatus($"RSA密钥对生成完成 - {keySize}位 {comboRSAKeyFormat.SelectedItem}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成RSA密钥对失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成RSA密钥对失败");
            }
        }

        private void btnImportRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "密钥文件 (*.txt;*.key;*.xml)|*.txt;*.key;*.xml|所有文件 (*.*)|*.*";
                    openFileDialog.Title = "导入RSA密钥文件";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);

                        // 尝试解析文件内容
                        if (content.Contains("<RSAKeyValue>") || content.Contains("-----BEGIN"))
                        {
                            // 如果是XML格式或PEM格式，将公钥和私钥分别存储在一个文件中
                            // 或者按特定格式分割
                            string[] parts = content.Split(new string[] { "-----END", "</RSAKeyValue>" }, StringSplitOptions.RemoveEmptyEntries);

                            if (parts.Length >= 2)
                            {
                                textRSAPublicKey.Text = parts[0].Trim() + (content.Contains("-----END") ? "-----END PUBLIC KEY-----" : "</RSAKeyValue>");
                                textRSAPrivateKey.Text = parts[1].Trim();
                            }
                            else
                            {
                                // 如果只有一个密钥，判断是公钥还是私钥
                                if (content.Contains("PRIVATE") || content.Contains("<D>"))
                                {
                                    textRSAPrivateKey.Text = content.Trim();
                                }
                                else
                                {
                                    textRSAPublicKey.Text = content.Trim();
                                }
                            }
                        }
                        else
                        {
                            // 简单格式：每行一个密钥
                            string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                            if (lines.Length >= 2)
                            {
                                textRSAPublicKey.Text = lines[0].Trim();
                                textRSAPrivateKey.Text = lines[1].Trim();
                            }
                            else if (lines.Length == 1)
                            {
                                // 如果只有一行，先清空然后设置
                                textRSAPublicKey.Text = "";
                                textRSAPrivateKey.Text = "";
                                textRSAPublicKey.Text = lines[0].Trim();
                            }
                        }

                        SetStatus("RSA密钥导入成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导入RSA密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导入RSA密钥失败");
            }
        }

        private void btnExportRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSAPublicKey.Text) && string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("请先生成或输入RSA密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "密钥文件 (*.txt)|*.txt|XML文件 (*.xml)|*.xml|所有文件 (*.*)|*.*";
                    saveFileDialog.Title = "导出RSA密钥文件";
                    saveFileDialog.FileName = "rsa_keys.txt";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        StringBuilder content = new StringBuilder();

                        if (!string.IsNullOrEmpty(textRSAPublicKey.Text))
                        {
                            content.AppendLine("公钥：");
                            content.AppendLine(textRSAPublicKey.Text);
                            content.AppendLine();
                        }

                        if (!string.IsNullOrEmpty(textRSAPrivateKey.Text))
                        {
                            content.AppendLine("私钥：");
                            content.AppendLine(textRSAPrivateKey.Text);
                        }

                        File.WriteAllText(saveFileDialog.FileName, content.ToString(), Encoding.UTF8);
                        SetStatus("RSA密钥导出成功");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"导出RSA密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("导出RSA密钥失败");
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

                // 输入
                RSAUtil.RSAKeyType rsaKeyType = (RSAUtil.RSAKeyType)Enum.Parse(typeof(RSAUtil.RSAKeyType), comboRSAKeyFormat.SelectedIndex.ToString());
                RSAUtil.RSAPadding paddingFormat = (RSAUtil.RSAPadding)Enum.Parse(typeof(RSAUtil.RSAPadding), comboRSAKeyPadding.SelectedItem.ToString());
                // 密文格式
                RSAUtil.RSAKeyFormat outputFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), comboRSAEncryptOutputFormat.SelectedItem.ToString());
                // 密钥格式
                RSAUtil.RSAKeyFormat inputFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), comboRSAKeyOutputFormat.SelectedItem.ToString());
                var cipherText = RSAUtil.Encrypt(textRSAPlainText.Text, textRSAPublicKey.Text, inputFormat, rsaKeyType, paddingFormat, outputFormat);
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

                string paddingText = comboRSAKeyPadding.SelectedItem.ToString();
                RSAUtil.RSAKeyType rsaKeyType = (RSAUtil.RSAKeyType)Enum.Parse(typeof(RSAUtil.RSAKeyType), comboRSAKeyFormat.SelectedIndex.ToString());
                RSAUtil.RSAPadding paddingFormat = (RSAUtil.RSAPadding)Enum.Parse(typeof(RSAUtil.RSAPadding), paddingText);
                // 密文格式
                RSAUtil.RSAKeyFormat outputFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), comboRSAEncryptOutputFormat.SelectedItem.ToString());
                // 密钥格式
                RSAUtil.RSAKeyFormat inputFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), comboRSAKeyOutputFormat.SelectedItem.ToString());
                string plainText = RSAUtil.Decrypt(textRSACipherText.Text, textRSAPrivateKey.Text, inputFormat, rsaKeyType, paddingFormat, outputFormat);
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

                string comboRSASignAlgmFormatText = comboRSASignAlgmFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyType rsaKeyType = (RSAUtil.RSAKeyType)Enum.Parse(typeof(RSAUtil.RSAKeyType), comboRSAKeyFormat.SelectedIndex.ToString());

                // hash算法类型
                RSAUtil.SignatureAlgorithm signAlgmFormat = (RSAUtil.SignatureAlgorithm)Enum.Parse(typeof(RSAUtil.SignatureAlgorithm), comboRSASignAlgmFormat.SelectedIndex.ToString());
                // 签名结果类型
                RSAUtil.RSAKeyFormat signOutputFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), comboRSASignOutputFormat.SelectedItem.ToString());
                // 密钥格式
                RSAUtil.RSAKeyFormat inputFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), comboRSAKeyOutputFormat.SelectedItem.ToString());

                string signature = RSAUtil.Sign(textRSASignData.Text, textRSAPrivateKey.Text, inputFormat, rsaKeyType, signAlgmFormat, signOutputFormat);
                textRSASignature.Text = signature;

                SetStatus($"RSA签名完成 - 使用{comboRSASignAlgmFormatText}算法");
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

                string comboRSASignAlgmFormatText = comboRSASignAlgmFormat.SelectedItem.ToString();

                // 签名类型
                RSAUtil.RSAKeyType rsaKeyType = (RSAUtil.RSAKeyType)Enum.Parse(typeof(RSAUtil.RSAKeyType), comboRSAKeyFormat.SelectedIndex.ToString());

                // hash算法类型
                RSAUtil.SignatureAlgorithm signAlgmFormat = (RSAUtil.SignatureAlgorithm)Enum.Parse(typeof(RSAUtil.SignatureAlgorithm), comboRSASignAlgmFormat.SelectedIndex.ToString());
                // 签名结果格式
                RSAUtil.RSAKeyFormat inputFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), comboRSASignOutputFormat.SelectedItem.ToString());
                // 公钥格式
                RSAUtil.RSAKeyFormat publicKeyKeyFormat = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), comboRSAKeyOutputFormat.SelectedItem.ToString());

                bool verifyResult = RSAUtil.Verify(textRSASignData.Text, textRSASignature.Text, textRSAPublicKey.Text, publicKeyKeyFormat, rsaKeyType, signAlgmFormat, inputFormat);

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

        private void ComboRSAEncryptOutputFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            label6.Text = $"密文({comboRSAEncryptOutputFormat.SelectedItem}):";
        }

        private void ComboRSASignOutputFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            label8.Text = $"签名({comboRSASignOutputFormat.SelectedItem}):";
        }

        private void ComboRSAKeyOutputFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            label3.Text = $"公钥({comboRSAKeyOutputFormat.SelectedItem}):";
            label4.Text = $"私钥({comboRSAKeyOutputFormat.SelectedItem}):";
        }

        #endregion
    }
}
