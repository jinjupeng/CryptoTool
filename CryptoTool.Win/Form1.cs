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
            // ��ʼ��Ĭ��ֵ
            comboRSAKeySize.SelectedIndex = 1; // 2048
            comboRSAKeyFormat.SelectedIndex = 0; // XML
            comboRSAType.SelectedIndex = 1; // RSA2
            comboSM4Mode.SelectedIndex = 0; // ECB
            comboSM4Padding.SelectedIndex = 0; // PKCS7
            
            SetStatus("����");
        }

        #region RSA����

        private void btnGenerateRSAKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("��������RSA��Կ��...");
                
                int keySize = int.Parse(comboRSAKeySize.SelectedItem.ToString());
                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);
                
                var keyPair = RSAUtil.CreateRSAKey(keySize, format);
                
                textRSAPublicKey.Text = keyPair.Key;
                textRSAPrivateKey.Text = keyPair.Value;
                
                SetStatus($"RSA��Կ��������� - {keySize}λ {formatText}��ʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����RSA��Կ��ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����RSA��Կ��ʧ��");
            }
        }

        private void btnRSAEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSAPlainText.Text))
                {
                    MessageBox.Show("���������ģ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPublicKey.Text))
                {
                    MessageBox.Show("�������ɻ�����RSA��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���RSA����...");

                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string cipherText = RSAUtil.EncryptByRSA(textRSAPlainText.Text, textRSAPublicKey.Text, format);
                textRSACipherText.Text = cipherText;

                SetStatus("RSA�������");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA����ʧ��");
            }
        }

        private void btnRSADecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSACipherText.Text))
                {
                    MessageBox.Show("���������ģ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("�������ɻ�����RSA˽Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���RSA����...");

                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string plainText = RSAUtil.DecryptByRSA(textRSACipherText.Text, textRSAPrivateKey.Text, format);
                textRSAPlainText.Text = plainText;

                SetStatus("RSA�������");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSA����ʧ��");
            }
        }

        private void btnRSASign_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSASignData.Text))
                {
                    MessageBox.Show("������Ҫǩ����ԭ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPrivateKey.Text))
                {
                    MessageBox.Show("�������ɻ�����RSA˽Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���RSAǩ��...");

                string rsaTypeText = comboRSAType.SelectedItem.ToString();
                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                
                RSAUtil.RSAType rsaType = (RSAUtil.RSAType)Enum.Parse(typeof(RSAUtil.RSAType), rsaTypeText);
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                string signature = RSAUtil.HashAndSignString(textRSASignData.Text, textRSAPrivateKey.Text, rsaType, format);
                textRSASignature.Text = signature;

                SetStatus($"RSAǩ����� - ʹ��{rsaTypeText}�㷨");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSAǩ��ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("RSAǩ��ʧ��");
            }
        }

        private void btnRSAVerify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textRSASignData.Text))
                {
                    MessageBox.Show("������ԭ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSASignature.Text))
                {
                    MessageBox.Show("������ǩ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textRSAPublicKey.Text))
                {
                    MessageBox.Show("�������ɻ�����RSA��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���RSA��ǩ...");

                string rsaTypeText = comboRSAType.SelectedItem.ToString();
                string formatText = comboRSAKeyFormat.SelectedItem.ToString();
                
                RSAUtil.RSAType rsaType = (RSAUtil.RSAType)Enum.Parse(typeof(RSAUtil.RSAType), rsaTypeText);
                RSAUtil.RSAKeyFormat format = (RSAUtil.RSAKeyFormat)Enum.Parse(typeof(RSAUtil.RSAKeyFormat), formatText);

                bool verifyResult = RSAUtil.VerifySigned(textRSASignData.Text, textRSASignature.Text, textRSAPublicKey.Text, rsaType, format);
                
                labelRSAVerifyResult.Text = $"��ǩ���: {(verifyResult ? "��֤�ɹ�" : "��֤ʧ��")}";
                labelRSAVerifyResult.ForeColor = verifyResult ? Color.Green : Color.Red;

                SetStatus($"RSA��ǩ��� - {(verifyResult ? "��֤�ɹ�" : "��֤ʧ��")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"RSA��ǩʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelRSAVerifyResult.Text = "��ǩ���: ��֤�쳣";
                labelRSAVerifyResult.ForeColor = Color.Red;
                SetStatus("RSA��ǩʧ��");
            }
        }

        #endregion

        #region SM4����

        private void btnGenerateSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("��������SM4��Կ...");
                string key = SM4Util.GenerateKey();
                textSM4Key.Text = key;
                SetStatus("SM4��Կ�������");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����SM4��Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����SM4��Կʧ��");
            }
        }

        private void btnGenerateSM4IV_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("��������SM4��ʼ����...");
                string iv = SM4Util.GenerateIV();
                textSM4IV.Text = iv;
                SetStatus("SM4��ʼ�����������");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����SM4��ʼ����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����SM4��ʼ����ʧ��");
            }
        }

        private void btnSM4Encrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4PlainText.Text))
                {
                    MessageBox.Show("���������ģ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("�������ɻ�����SM4��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboSM4Mode.SelectedItem.ToString();
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBCģʽ��Ҫ��ʼ�������������ɻ������ʼ������", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���SM4����...");

                string paddingText = comboSM4Padding.SelectedItem.ToString();
                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);

                // ��Base64��Կת��Ϊ�ַ�����Կ�����ڴ��ݸ�SM4Util���ַ���������
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
                SetStatus($"SM4������� - ʹ��{mode}ģʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM4����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM4����ʧ��");
            }
        }

        private void btnSM4Decrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4CipherText.Text))
                {
                    MessageBox.Show("���������ģ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("�������ɻ�����SM4��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboSM4Mode.SelectedItem.ToString();
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBCģʽ��Ҫ��ʼ�������������ɻ������ʼ������", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���SM4����...");

                string paddingText = comboSM4Padding.SelectedItem.ToString();
                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);

                // ��Base64��Կת��Ϊ�ַ�����Կ
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
                SetStatus($"SM4������� - ʹ��{mode}ģʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM4����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM4����ʧ��");
            }
        }

        private void comboSM4Mode_SelectedIndexChanged(object sender, EventArgs e)
        {
            // ��ѡ��ECBģʽʱ�����ó�ʼ������ؿؼ�
            bool isCBC = comboSM4Mode.SelectedItem.ToString() == "CBC";
            textSM4IV.Enabled = isCBC;
            btnGenerateSM4IV.Enabled = isCBC;
            
            if (!isCBC)
            {
                textSM4IV.Text = "";
            }
        }

        #endregion

        #region ��������

        private void SetStatus(string message)
        {
            toolStripStatusLabel1.Text = message;
            Application.DoEvents();
        }

        #endregion
    }
}
