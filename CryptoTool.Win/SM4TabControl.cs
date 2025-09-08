using CryptoTool.Common.GM;
using System.Text;

namespace CryptoTool.Win
{
    public partial class SM4TabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public SM4TabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            comboSM4Mode.SelectedIndex = 0; // ECB
            comboSM4Padding.SelectedIndex = 0; // PKCS7
            comboSM4KeyFormat.SelectedIndex = 0; // Base64
            comboSM4IVFormat.SelectedIndex = 0; // Base64
            comboSM4PlaintextFormat.SelectedIndex = 0; // Text
            comboSM4CiphertextFormat.SelectedIndex = 0; // Base64
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        public void UpdateKeyFromMedicare(string key)
        {
            textSM4Key.Text = key;
            comboSM4KeyFormat.SelectedItem = "Hex";
        }

        #region SM4����

        private void btnGenerateSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("��������SM4��Կ...");

                string formatText = comboSM4KeyFormat.SelectedItem.ToString();
                SM4Util.FormatType format = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), formatText);

                string key = SM4Util.GenerateKey(format);
                textSM4Key.Text = key;
                SetStatus($"SM4��Կ������� - {formatText}��ʽ");
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

                string formatText = comboSM4IVFormat.SelectedItem.ToString();
                SM4Util.FormatType format = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), formatText);

                string iv = SM4Util.GenerateIV(format);
                textSM4IV.Text = iv;
                SetStatus($"SM4��ʼ����������� - {formatText}��ʽ");
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
                string keyFormatText = comboSM4KeyFormat.SelectedItem.ToString();
                string plaintextFormatText = comboSM4PlaintextFormat.SelectedItem.ToString();
                string ciphertextFormatText = comboSM4CiphertextFormat.SelectedItem.ToString();

                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);
                SM4Util.FormatType keyFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), keyFormatText);
                SM4Util.FormatType plaintextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), plaintextFormatText);
                SM4Util.FormatType ciphertextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ciphertextFormatText);

                string cipherText;
                if (mode == "ECB")
                {
                    cipherText = SM4Util.EncryptEcbWithFormat(textSM4PlainText.Text, textSM4Key.Text, keyFormat, plaintextFormat, ciphertextFormat, padding);
                }
                else // CBC
                {
                    string ivFormatText = comboSM4IVFormat.SelectedItem.ToString();
                    SM4Util.FormatType ivFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ivFormatText);
                    cipherText = SM4Util.EncryptCbcWithFormat(textSM4PlainText.Text, textSM4Key.Text, textSM4IV.Text, keyFormat, ivFormat, plaintextFormat, ciphertextFormat, padding);
                }

                textSM4CipherText.Text = cipherText;
                SetStatus($"SM4������� - ʹ��{mode}ģʽ������{plaintextFormatText}��ʽ�����{ciphertextFormatText}��ʽ");
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
                string keyFormatText = comboSM4KeyFormat.SelectedItem.ToString();
                string plaintextFormatText = comboSM4PlaintextFormat.SelectedItem.ToString();
                string ciphertextFormatText = comboSM4CiphertextFormat.SelectedItem.ToString();

                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);
                SM4Util.FormatType keyFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), keyFormatText);
                SM4Util.FormatType plaintextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), plaintextFormatText);
                SM4Util.FormatType ciphertextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ciphertextFormatText);

                string plainText;
                if (mode == "ECB")
                {
                    plainText = SM4Util.DecryptEcbWithFormat(textSM4CipherText.Text, textSM4Key.Text, keyFormat, ciphertextFormat, plaintextFormat, padding);
                }
                else // CBC
                {
                    string ivFormatText = comboSM4IVFormat.SelectedItem.ToString();
                    SM4Util.FormatType ivFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ivFormatText);
                    plainText = SM4Util.DecryptCbcWithFormat(textSM4CipherText.Text, textSM4Key.Text, textSM4IV.Text, keyFormat, ivFormat, ciphertextFormat, plaintextFormat, padding);
                }

                textSM4PlainText.Text = plainText;
                SetStatus($"SM4������� - ʹ��{mode}ģʽ������{ciphertextFormatText}��ʽ�����{plaintextFormatText}��ʽ");
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
            comboSM4IVFormat.Enabled = isCBC;

            if (!isCBC)
            {
                textSM4IV.Text = "";
            }
        }

        private void comboSM4IVFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            // ����ʽ�仯ʱ�������ǰ��IV���ݣ�����ת����ʽ
            if (string.IsNullOrEmpty(textSM4IV.Text)) return;

            try
            {
                // �ݲ�ʵ���Զ���ʽת�����������ת��
                // �û���Ҫ��������IV���ֶ�������ȷ��ʽ��IV
            }
            catch
            {
                // ��ʽת��ʧ�ܣ�����
            }
        }

        #endregion
    }
}