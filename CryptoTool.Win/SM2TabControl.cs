using CryptoTool.Common.GM;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoTool.Win
{
    public partial class SM2TabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public SM2TabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            comboSM2KeyFormat.SelectedIndex = 0; // Base64
            comboSM2CipherFormat.SelectedIndex = 0; // C1C3C2
            comboSM2SignFormat.SelectedIndex = 0; // ASN1
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region SM2����

        private void btnGenerateSM2Key_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("��������SM2��Կ��...");

                var keyPair = SM2Util.GenerateKeyPair();
                var publicKey = (ECPublicKeyParameters)keyPair.Public;
                var privateKey = (ECPrivateKeyParameters)keyPair.Private;

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();

                if (formatText == "Base64")
                {
                    textSM2PublicKey.Text = SM2Util.PublicKeyToRawBase64(publicKey);
                    textSM2PrivateKey.Text = SM2Util.PrivateKeyToRawBase64(privateKey);
                }
                else // Hex
                {
                    textSM2PublicKey.Text = SM2Util.PublicKeyToHex(publicKey);
                    textSM2PrivateKey.Text = SM2Util.PrivateKeyToHex(privateKey);
                }

                SetStatus($"SM2��Կ��������� - {formatText}��ʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����SM2��Կ��ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����SM2��Կ��ʧ��");
            }
        }

        private void btnImportSM2Key_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "��Կ�ļ� (*.txt;*.key)|*.txt;*.key|�����ļ� (*.*)|*.*";
                    openFileDialog.Title = "����SM2��Կ�ļ�";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                        if (lines.Length >= 2)
                        {
                            textSM2PublicKey.Text = lines[0].Trim();
                            textSM2PrivateKey.Text = lines[1].Trim();
                            SetStatus("SM2��Կ����ɹ�");
                        }
                        else
                        {
                            MessageBox.Show("��Կ�ļ���ʽ����Ӧ������Կ��˽Կ���С�", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����SM2��Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����SM2��Կʧ��");
            }
        }

        private void btnExportSM2Key_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2PublicKey.Text) || string.IsNullOrEmpty(textSM2PrivateKey.Text))
                {
                    MessageBox.Show("�������ɻ�����SM2��Կ�ԣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "��Կ�ļ� (*.txt)|*.txt|�����ļ� (*.*)|*.*";
                    saveFileDialog.Title = "����SM2��Կ�ļ�";
                    saveFileDialog.FileName = "sm2_keys.txt";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = $"��Կ��\r\n{textSM2PublicKey.Text}\r\n\r\n˽Կ��\r\n{textSM2PrivateKey.Text}";
                        File.WriteAllText(saveFileDialog.FileName, content, Encoding.UTF8);
                        SetStatus("SM2��Կ�����ɹ�");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"����SM2��Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("����SM2��Կʧ��");
            }
        }

        private void btnSM2Encrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2PlainText.Text))
                {
                    MessageBox.Show("���������ģ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2PublicKey.Text))
                {
                    MessageBox.Show("�������ɻ�����SM2��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���SM2����...");

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();
                string cipherFormatText = comboSM2CipherFormat.SelectedItem.ToString();

                SM2Util.SM2CipherFormat cipherFormat = (SM2Util.SM2CipherFormat)Enum.Parse(typeof(SM2Util.SM2CipherFormat), cipherFormatText);

                string cipherText;
                if (formatText == "Base64")
                {
                    cipherText = SM2Util.Encrypt(textSM2PlainText.Text, textSM2PublicKey.Text, Encoding.UTF8, cipherFormat);
                }
                else // Hex
                {
                    var publicKey = SM2Util.ParsePublicKeyFromHex(textSM2PublicKey.Text);
                    cipherText = SM2Util.Encrypt(textSM2PlainText.Text, publicKey, Encoding.UTF8, cipherFormat);
                }

                textSM2CipherText.Text = cipherText;
                SetStatus($"SM2������� - ʹ��{cipherFormatText}��ʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM2����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM2����ʧ��");
            }
        }

        private void btnSM2Decrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2CipherText.Text))
                {
                    MessageBox.Show("���������ģ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2PrivateKey.Text))
                {
                    MessageBox.Show("�������ɻ�����SM2˽Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���SM2����...");

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();
                string cipherFormatText = comboSM2CipherFormat.SelectedItem.ToString();

                SM2Util.SM2CipherFormat cipherFormat = (SM2Util.SM2CipherFormat)Enum.Parse(typeof(SM2Util.SM2CipherFormat), cipherFormatText);

                string plainText;
                if (formatText == "Base64")
                {
                    plainText = SM2Util.DecryptToString(textSM2CipherText.Text, textSM2PrivateKey.Text, Encoding.UTF8, cipherFormat);
                }
                else // Hex
                {
                    var privateKey = SM2Util.ParsePrivateKeyFromHex(textSM2PrivateKey.Text);
                    plainText = SM2Util.DecryptToString(textSM2CipherText.Text, privateKey, Encoding.UTF8, cipherFormat);
                }

                textSM2PlainText.Text = plainText;
                SetStatus($"SM2������� - ʹ��{cipherFormatText}��ʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM2����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM2����ʧ��");
            }
        }

        private void btnSM2Sign_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2SignData.Text))
                {
                    MessageBox.Show("������Ҫǩ����ԭ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2PrivateKey.Text))
                {
                    MessageBox.Show("�������ɻ�����SM2˽Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���SM2ǩ��...");

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();
                string signFormatText = comboSM2SignFormat.SelectedItem.ToString();

                SM2Util.SM2SignatureFormat signFormat = (SM2Util.SM2SignatureFormat)Enum.Parse(typeof(SM2Util.SM2SignatureFormat), signFormatText);

                string signature;
                if (formatText == "Base64")
                {
                    signature = SM2Util.SignSm3WithSm2(textSM2SignData.Text, textSM2PrivateKey.Text, Encoding.UTF8, signFormat);
                }
                else // Hex
                {
                    var privateKey = SM2Util.ParsePrivateKeyFromHex(textSM2PrivateKey.Text);
                    signature = SM2Util.SignSm3WithSm2(textSM2SignData.Text, privateKey, Encoding.UTF8, signFormat);
                }

                textSM2Signature.Text = signature;
                SetStatus($"SM2ǩ����� - ʹ��{signFormatText}��ʽ");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM2ǩ��ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM2ǩ��ʧ��");
            }
        }

        private void btnSM2Verify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM2SignData.Text))
                {
                    MessageBox.Show("������ԭ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2Signature.Text))
                {
                    MessageBox.Show("������ǩ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM2PublicKey.Text))
                {
                    MessageBox.Show("�������ɻ�����SM2��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ���SM2��ǩ...");

                string formatText = comboSM2KeyFormat.SelectedItem.ToString();
                string signFormatText = comboSM2SignFormat.SelectedItem.ToString();

                SM2Util.SM2SignatureFormat signFormat = (SM2Util.SM2SignatureFormat)Enum.Parse(typeof(SM2Util.SM2SignatureFormat), signFormatText);

                bool verifyResult;
                if (formatText == "Base64")
                {
                    verifyResult = SM2Util.VerifySm3WithSm2(textSM2SignData.Text, textSM2Signature.Text, textSM2PublicKey.Text, Encoding.UTF8, signFormat);
                }
                else // Hex
                {
                    var publicKey = SM2Util.ParsePublicKeyFromHex(textSM2PublicKey.Text);
                    verifyResult = SM2Util.VerifySm3WithSm2(textSM2SignData.Text, textSM2Signature.Text, publicKey, Encoding.UTF8, signFormat);
                }

                labelSM2VerifyResult.Text = $"��ǩ���: {(verifyResult ? "��֤�ɹ�" : "��֤ʧ��")}";
                labelSM2VerifyResult.ForeColor = verifyResult ? Color.Green : Color.Red;

                SetStatus($"SM2��ǩ��� - {(verifyResult ? "��֤�ɹ�" : "��֤ʧ��")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM2��ǩʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelSM2VerifyResult.Text = "��ǩ���: ��֤�쳣";
                labelSM2VerifyResult.ForeColor = Color.Red;
                SetStatus("SM2��ǩʧ��");
            }
        }

        #endregion
    }
}