namespace CryptoTool.Win
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            tabControl1 = new TabControl();
            tabRSA = new TabPage();
            groupBoxRSASign = new GroupBox();
            labelRSAVerifyResult = new Label();
            label9 = new Label();
            comboRSAType = new ComboBox();
            label8 = new Label();
            textRSASignature = new TextBox();
            label7 = new Label();
            textRSASignData = new TextBox();
            btnRSAVerify = new Button();
            btnRSASign = new Button();
            groupBoxRSAEncrypt = new GroupBox();
            label6 = new Label();
            textRSACipherText = new TextBox();
            label5 = new Label();
            textRSAPlainText = new TextBox();
            btnRSADecrypt = new Button();
            btnRSAEncrypt = new Button();
            groupBoxRSAKeys = new GroupBox();
            btnExportRSAKey = new Button();
            btnImportRSAKey = new Button();
            label4 = new Label();
            textRSAPrivateKey = new TextBox();
            label3 = new Label();
            textRSAPublicKey = new TextBox();
            label2 = new Label();
            comboRSAKeyFormat = new ComboBox();
            label1 = new Label();
            comboRSAKeySize = new ComboBox();
            btnGenerateRSAKey = new Button();
            tabSM4 = new TabPage();
            groupBoxSM4Encrypt = new GroupBox();
            labelSM4CiphertextFormat = new Label();
            comboSM4CiphertextFormat = new ComboBox();
            labelSM4PlaintextFormat = new Label();
            comboSM4PlaintextFormat = new ComboBox();
            label15 = new Label();
            comboSM4Padding = new ComboBox();
            label14 = new Label();
            comboSM4Mode = new ComboBox();
            label13 = new Label();
            textSM4CipherText = new TextBox();
            label12 = new Label();
            textSM4PlainText = new TextBox();
            btnSM4Decrypt = new Button();
            btnSM4Encrypt = new Button();
            groupBoxSM4Keys = new GroupBox();
            btnExportSM4Key = new Button();
            btnImportSM4Key = new Button();
            labelSM4IVFormat = new Label();
            comboSM4IVFormat = new ComboBox();
            labelSM4KeyFormat = new Label();
            comboSM4KeyFormat = new ComboBox();
            label11 = new Label();
            textSM4IV = new TextBox();
            label10 = new Label();
            textSM4Key = new TextBox();
            btnGenerateSM4IV = new Button();
            btnGenerateSM4Key = new Button();
            tabSM2 = new TabPage();
            groupBoxSM2Sign = new GroupBox();
            labelSM2VerifyResult = new Label();
            label24 = new Label();
            textSM2Signature = new TextBox();
            label23 = new Label();
            textSM2SignData = new TextBox();
            btnSM2Verify = new Button();
            btnSM2Sign = new Button();
            label22 = new Label();
            comboSM2SignFormat = new ComboBox();
            groupBoxSM2Encrypt = new GroupBox();
            label21 = new Label();
            textSM2CipherText = new TextBox();
            label20 = new Label();
            textSM2PlainText = new TextBox();
            btnSM2Decrypt = new Button();
            btnSM2Encrypt = new Button();
            label19 = new Label();
            comboSM2CipherFormat = new ComboBox();
            groupBoxSM2Keys = new GroupBox();
            btnExportSM2Key = new Button();
            btnImportSM2Key = new Button();
            label18 = new Label();
            textSM2PrivateKey = new TextBox();
            label17 = new Label();
            textSM2PublicKey = new TextBox();
            label16 = new Label();
            comboSM2KeyFormat = new ComboBox();
            btnGenerateSM2Key = new Button();
            statusStrip1 = new StatusStrip();
            toolStripStatusLabel1 = new ToolStripStatusLabel();
            tabControl1.SuspendLayout();
            tabRSA.SuspendLayout();
            groupBoxRSASign.SuspendLayout();
            groupBoxRSAEncrypt.SuspendLayout();
            groupBoxRSAKeys.SuspendLayout();
            tabSM4.SuspendLayout();
            groupBoxSM4Encrypt.SuspendLayout();
            groupBoxSM4Keys.SuspendLayout();
            tabSM2.SuspendLayout();
            groupBoxSM2Sign.SuspendLayout();
            groupBoxSM2Encrypt.SuspendLayout();
            groupBoxSM2Keys.SuspendLayout();
            statusStrip1.SuspendLayout();
            SuspendLayout();
            // 
            // tabControl1
            // 
            tabControl1.Controls.Add(tabRSA);
            tabControl1.Controls.Add(tabSM4);
            tabControl1.Controls.Add(tabSM2);
            tabControl1.Dock = DockStyle.Fill;
            tabControl1.Location = new Point(0, 0);
            tabControl1.Margin = new Padding(4);
            tabControl1.Name = "tabControl1";
            tabControl1.SelectedIndex = 0;
            tabControl1.Size = new Size(1286, 765);
            tabControl1.TabIndex = 0;
            // 
            // tabRSA
            // 
            tabRSA.Controls.Add(groupBoxRSASign);
            tabRSA.Controls.Add(groupBoxRSAEncrypt);
            tabRSA.Controls.Add(groupBoxRSAKeys);
            tabRSA.Location = new Point(4, 29);
            tabRSA.Margin = new Padding(4);
            tabRSA.Name = "tabRSA";
            tabRSA.Padding = new Padding(4);
            tabRSA.Size = new Size(1278, 732);
            tabRSA.TabIndex = 0;
            tabRSA.Text = "RSA算法";
            tabRSA.UseVisualStyleBackColor = true;
            // 
            // groupBoxRSASign
            // 
            groupBoxRSASign.Controls.Add(labelRSAVerifyResult);
            groupBoxRSASign.Controls.Add(label9);
            groupBoxRSASign.Controls.Add(comboRSAType);
            groupBoxRSASign.Controls.Add(label8);
            groupBoxRSASign.Controls.Add(textRSASignature);
            groupBoxRSASign.Controls.Add(label7);
            groupBoxRSASign.Controls.Add(textRSASignData);
            groupBoxRSASign.Controls.Add(btnRSAVerify);
            groupBoxRSASign.Controls.Add(btnRSASign);
            groupBoxRSASign.Location = new Point(8, 468);
            groupBoxRSASign.Margin = new Padding(4);
            groupBoxRSASign.Name = "groupBoxRSASign";
            groupBoxRSASign.Padding = new Padding(4);
            groupBoxRSASign.Size = new Size(1260, 256);
            groupBoxRSASign.TabIndex = 2;
            groupBoxRSASign.TabStop = false;
            groupBoxRSASign.Text = "RSA数字签名";
            // 
            // labelRSAVerifyResult
            // 
            labelRSAVerifyResult.AutoSize = true;
            labelRSAVerifyResult.Location = new Point(514, 214);
            labelRSAVerifyResult.Margin = new Padding(4, 0, 4, 0);
            labelRSAVerifyResult.Name = "labelRSAVerifyResult";
            labelRSAVerifyResult.Size = new Size(73, 20);
            labelRSAVerifyResult.TabIndex = 8;
            labelRSAVerifyResult.Text = "验签结果:";
            // 
            // label9
            // 
            label9.AutoSize = true;
            label9.Location = new Point(19, 33);
            label9.Margin = new Padding(4, 0, 4, 0);
            label9.Name = "label9";
            label9.Size = new Size(73, 20);
            label9.TabIndex = 7;
            label9.Text = "签名类型:";
            // 
            // comboRSAType
            // 
            comboRSAType.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSAType.FormattingEnabled = true;
            comboRSAType.Items.AddRange(new object[] { "RSA", "RSA2" });
            comboRSAType.Location = new Point(103, 29);
            comboRSAType.Margin = new Padding(4);
            comboRSAType.Name = "comboRSAType";
            comboRSAType.Size = new Size(127, 28);
            comboRSAType.TabIndex = 6;
            // 
            // label8
            // 
            label8.AutoSize = true;
            label8.Location = new Point(19, 145);
            label8.Margin = new Padding(4, 0, 4, 0);
            label8.Name = "label8";
            label8.Size = new Size(43, 20);
            label8.TabIndex = 5;
            label8.Text = "签名:";
            // 
            // textRSASignature
            // 
            textRSASignature.Location = new Point(103, 141);
            textRSASignature.Margin = new Padding(4);
            textRSASignature.Multiline = true;
            textRSASignature.Name = "textRSASignature";
            textRSASignature.ScrollBars = ScrollBars.Both;
            textRSASignature.Size = new Size(1137, 58);
            textRSASignature.TabIndex = 4;
            // 
            // label7
            // 
            label7.AutoSize = true;
            label7.Location = new Point(19, 74);
            label7.Margin = new Padding(4, 0, 4, 0);
            label7.Name = "label7";
            label7.Size = new Size(73, 20);
            label7.TabIndex = 3;
            label7.Text = "原文数据:";
            // 
            // textRSASignData
            // 
            textRSASignData.Location = new Point(103, 71);
            textRSASignData.Margin = new Padding(4);
            textRSASignData.Multiline = true;
            textRSASignData.Name = "textRSASignData";
            textRSASignData.ScrollBars = ScrollBars.Both;
            textRSASignData.Size = new Size(1137, 58);
            textRSASignData.TabIndex = 2;
            // 
            // btnRSAVerify
            // 
            btnRSAVerify.Location = new Point(386, 29);
            btnRSAVerify.Margin = new Padding(4);
            btnRSAVerify.Name = "btnRSAVerify";
            btnRSAVerify.Size = new Size(103, 28);
            btnRSAVerify.TabIndex = 1;
            btnRSAVerify.Text = "验签";
            btnRSAVerify.UseVisualStyleBackColor = true;
            btnRSAVerify.Click += btnRSAVerify_Click;
            // 
            // btnRSASign
            // 
            btnRSASign.Location = new Point(257, 29);
            btnRSASign.Margin = new Padding(4);
            btnRSASign.Name = "btnRSASign";
            btnRSASign.Size = new Size(103, 28);
            btnRSASign.TabIndex = 0;
            btnRSASign.Text = "签名";
            btnRSASign.UseVisualStyleBackColor = true;
            btnRSASign.Click += btnRSASign_Click;
            // 
            // groupBoxRSAEncrypt
            // 
            groupBoxRSAEncrypt.Controls.Add(label6);
            groupBoxRSAEncrypt.Controls.Add(textRSACipherText);
            groupBoxRSAEncrypt.Controls.Add(label5);
            groupBoxRSAEncrypt.Controls.Add(textRSAPlainText);
            groupBoxRSAEncrypt.Controls.Add(btnRSADecrypt);
            groupBoxRSAEncrypt.Controls.Add(btnRSAEncrypt);
            groupBoxRSAEncrypt.Location = new Point(8, 249);
            groupBoxRSAEncrypt.Margin = new Padding(4);
            groupBoxRSAEncrypt.Name = "groupBoxRSAEncrypt";
            groupBoxRSAEncrypt.Padding = new Padding(4);
            groupBoxRSAEncrypt.Size = new Size(1260, 212);
            groupBoxRSAEncrypt.TabIndex = 1;
            groupBoxRSAEncrypt.TabStop = false;
            groupBoxRSAEncrypt.Text = "RSA加密解密";
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new Point(19, 104);
            label6.Margin = new Padding(4, 0, 4, 0);
            label6.Name = "label6";
            label6.Size = new Size(43, 20);
            label6.TabIndex = 5;
            label6.Text = "密文:";
            // 
            // textRSACipherText
            // 
            textRSACipherText.Location = new Point(103, 100);
            textRSACipherText.Margin = new Padding(4);
            textRSACipherText.Multiline = true;
            textRSACipherText.Name = "textRSACipherText";
            textRSACipherText.ScrollBars = ScrollBars.Both;
            textRSACipherText.Size = new Size(1137, 58);
            textRSACipherText.TabIndex = 4;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new Point(19, 33);
            label5.Margin = new Padding(4, 0, 4, 0);
            label5.Name = "label5";
            label5.Size = new Size(43, 20);
            label5.TabIndex = 3;
            label5.Text = "明文:";
            // 
            // textRSAPlainText
            // 
            textRSAPlainText.Location = new Point(103, 29);
            textRSAPlainText.Margin = new Padding(4);
            textRSAPlainText.Multiline = true;
            textRSAPlainText.Name = "textRSAPlainText";
            textRSAPlainText.ScrollBars = ScrollBars.Both;
            textRSAPlainText.Size = new Size(1137, 58);
            textRSAPlainText.TabIndex = 2;
            // 
            // btnRSADecrypt
            // 
            btnRSADecrypt.Location = new Point(386, 165);
            btnRSADecrypt.Margin = new Padding(4);
            btnRSADecrypt.Name = "btnRSADecrypt";
            btnRSADecrypt.Size = new Size(103, 35);
            btnRSADecrypt.TabIndex = 1;
            btnRSADecrypt.Text = "解密";
            btnRSADecrypt.UseVisualStyleBackColor = true;
            btnRSADecrypt.Click += btnRSADecrypt_Click;
            // 
            // btnRSAEncrypt
            // 
            btnRSAEncrypt.Location = new Point(257, 165);
            btnRSAEncrypt.Margin = new Padding(4);
            btnRSAEncrypt.Name = "btnRSAEncrypt";
            btnRSAEncrypt.Size = new Size(103, 35);
            btnRSAEncrypt.TabIndex = 0;
            btnRSAEncrypt.Text = "加密";
            btnRSAEncrypt.UseVisualStyleBackColor = true;
            btnRSAEncrypt.Click += btnRSAEncrypt_Click;
            // 
            // groupBoxRSAKeys
            // 
            groupBoxRSAKeys.Controls.Add(btnExportRSAKey);
            groupBoxRSAKeys.Controls.Add(btnImportRSAKey);
            groupBoxRSAKeys.Controls.Add(label4);
            groupBoxRSAKeys.Controls.Add(textRSAPrivateKey);
            groupBoxRSAKeys.Controls.Add(label3);
            groupBoxRSAKeys.Controls.Add(textRSAPublicKey);
            groupBoxRSAKeys.Controls.Add(label2);
            groupBoxRSAKeys.Controls.Add(comboRSAKeyFormat);
            groupBoxRSAKeys.Controls.Add(label1);
            groupBoxRSAKeys.Controls.Add(comboRSAKeySize);
            groupBoxRSAKeys.Controls.Add(btnGenerateRSAKey);
            groupBoxRSAKeys.Location = new Point(8, 7);
            groupBoxRSAKeys.Margin = new Padding(4);
            groupBoxRSAKeys.Name = "groupBoxRSAKeys";
            groupBoxRSAKeys.Padding = new Padding(4);
            groupBoxRSAKeys.Size = new Size(1260, 235);
            groupBoxRSAKeys.TabIndex = 0;
            groupBoxRSAKeys.TabStop = false;
            groupBoxRSAKeys.Text = "RSA密钥生成";
            // 
            // btnExportRSAKey
            // 
            btnExportRSAKey.Location = new Point(771, 29);
            btnExportRSAKey.Margin = new Padding(4);
            btnExportRSAKey.Name = "btnExportRSAKey";
            btnExportRSAKey.Size = new Size(103, 28);
            btnExportRSAKey.TabIndex = 10;
            btnExportRSAKey.Text = "导出密钥";
            btnExportRSAKey.UseVisualStyleBackColor = true;
            btnExportRSAKey.Click += btnExportRSAKey_Click;
            // 
            // btnImportRSAKey
            // 
            btnImportRSAKey.Location = new Point(643, 29);
            btnImportRSAKey.Margin = new Padding(4);
            btnImportRSAKey.Name = "btnImportRSAKey";
            btnImportRSAKey.Size = new Size(103, 28);
            btnImportRSAKey.TabIndex = 9;
            btnImportRSAKey.Text = "导入密钥";
            btnImportRSAKey.UseVisualStyleBackColor = true;
            btnImportRSAKey.Click += btnImportRSAKey_Click;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new Point(19, 162);
            label4.Margin = new Padding(4, 0, 4, 0);
            label4.Name = "label4";
            label4.Size = new Size(43, 20);
            label4.TabIndex = 8;
            label4.Text = "私钥:";
            // 
            // textRSAPrivateKey
            // 
            textRSAPrivateKey.Location = new Point(103, 159);
            textRSAPrivateKey.Margin = new Padding(4);
            textRSAPrivateKey.Multiline = true;
            textRSAPrivateKey.Name = "textRSAPrivateKey";
            textRSAPrivateKey.ScrollBars = ScrollBars.Both;
            textRSAPrivateKey.Size = new Size(1137, 70);
            textRSAPrivateKey.TabIndex = 7;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(19, 80);
            label3.Margin = new Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new Size(43, 20);
            label3.TabIndex = 6;
            label3.Text = "公钥:";
            // 
            // textRSAPublicKey
            // 
            textRSAPublicKey.Location = new Point(103, 76);
            textRSAPublicKey.Margin = new Padding(4);
            textRSAPublicKey.Multiline = true;
            textRSAPublicKey.Name = "textRSAPublicKey";
            textRSAPublicKey.ScrollBars = ScrollBars.Both;
            textRSAPublicKey.Size = new Size(1137, 70);
            textRSAPublicKey.TabIndex = 5;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(251, 33);
            label2.Margin = new Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new Size(73, 20);
            label2.TabIndex = 4;
            label2.Text = "密钥格式:";
            // 
            // comboRSAKeyFormat
            // 
            comboRSAKeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSAKeyFormat.FormattingEnabled = true;
            comboRSAKeyFormat.Items.AddRange(new object[] { "XML", "PKCS1", "PKCS8", "Java" });
            comboRSAKeyFormat.Location = new Point(334, 29);
            comboRSAKeyFormat.Margin = new Padding(4);
            comboRSAKeyFormat.Name = "comboRSAKeyFormat";
            comboRSAKeyFormat.Size = new Size(127, 28);
            comboRSAKeyFormat.TabIndex = 3;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(19, 33);
            label1.Margin = new Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new Size(73, 20);
            label1.TabIndex = 2;
            label1.Text = "密钥长度:";
            // 
            // comboRSAKeySize
            // 
            comboRSAKeySize.DropDownStyle = ComboBoxStyle.DropDownList;
            comboRSAKeySize.FormattingEnabled = true;
            comboRSAKeySize.Items.AddRange(new object[] { "1024", "2048", "3072", "4096" });
            comboRSAKeySize.Location = new Point(103, 29);
            comboRSAKeySize.Margin = new Padding(4);
            comboRSAKeySize.Name = "comboRSAKeySize";
            comboRSAKeySize.Size = new Size(127, 28);
            comboRSAKeySize.TabIndex = 1;
            // 
            // btnGenerateRSAKey
            // 
            btnGenerateRSAKey.Location = new Point(489, 29);
            btnGenerateRSAKey.Margin = new Padding(4);
            btnGenerateRSAKey.Name = "btnGenerateRSAKey";
            btnGenerateRSAKey.Size = new Size(129, 28);
            btnGenerateRSAKey.TabIndex = 0;
            btnGenerateRSAKey.Text = "生成密钥对";
            btnGenerateRSAKey.UseVisualStyleBackColor = true;
            btnGenerateRSAKey.Click += btnGenerateRSAKey_Click;
            // 
            // tabSM4
            // 
            tabSM4.Controls.Add(groupBoxSM4Encrypt);
            tabSM4.Controls.Add(groupBoxSM4Keys);
            tabSM4.Location = new Point(4, 29);
            tabSM4.Margin = new Padding(4);
            tabSM4.Name = "tabSM4";
            tabSM4.Padding = new Padding(4);
            tabSM4.Size = new Size(1278, 732);
            tabSM4.TabIndex = 1;
            tabSM4.Text = "SM4算法";
            tabSM4.UseVisualStyleBackColor = true;
            // 
            // groupBoxSM4Encrypt
            // 
            groupBoxSM4Encrypt.Controls.Add(labelSM4CiphertextFormat);
            groupBoxSM4Encrypt.Controls.Add(comboSM4CiphertextFormat);
            groupBoxSM4Encrypt.Controls.Add(labelSM4PlaintextFormat);
            groupBoxSM4Encrypt.Controls.Add(comboSM4PlaintextFormat);
            groupBoxSM4Encrypt.Controls.Add(label15);
            groupBoxSM4Encrypt.Controls.Add(comboSM4Padding);
            groupBoxSM4Encrypt.Controls.Add(label14);
            groupBoxSM4Encrypt.Controls.Add(comboSM4Mode);
            groupBoxSM4Encrypt.Controls.Add(label13);
            groupBoxSM4Encrypt.Controls.Add(textSM4CipherText);
            groupBoxSM4Encrypt.Controls.Add(label12);
            groupBoxSM4Encrypt.Controls.Add(textSM4PlainText);
            groupBoxSM4Encrypt.Controls.Add(btnSM4Decrypt);
            groupBoxSM4Encrypt.Controls.Add(btnSM4Encrypt);
            groupBoxSM4Encrypt.Location = new Point(8, 226);
            groupBoxSM4Encrypt.Margin = new Padding(4);
            groupBoxSM4Encrypt.Name = "groupBoxSM4Encrypt";
            groupBoxSM4Encrypt.Padding = new Padding(4);
            groupBoxSM4Encrypt.Size = new Size(1260, 294);
            groupBoxSM4Encrypt.TabIndex = 1;
            groupBoxSM4Encrypt.TabStop = false;
            groupBoxSM4Encrypt.Text = "SM4加密解密";
            // 
            // labelSM4CiphertextFormat
            // 
            labelSM4CiphertextFormat.AutoSize = true;
            labelSM4CiphertextFormat.Location = new Point(534, 71);
            labelSM4CiphertextFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4CiphertextFormat.Name = "labelSM4CiphertextFormat";
            labelSM4CiphertextFormat.Size = new Size(73, 20);
            labelSM4CiphertextFormat.TabIndex = 13;
            labelSM4CiphertextFormat.Text = "密文格式:";
            // 
            // comboSM4CiphertextFormat
            // 
            comboSM4CiphertextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4CiphertextFormat.FormattingEnabled = true;
            comboSM4CiphertextFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboSM4CiphertextFormat.Location = new Point(617, 67);
            comboSM4CiphertextFormat.Margin = new Padding(4);
            comboSM4CiphertextFormat.Name = "comboSM4CiphertextFormat";
            comboSM4CiphertextFormat.Size = new Size(127, 28);
            comboSM4CiphertextFormat.TabIndex = 12;
            // 
            // labelSM4PlaintextFormat
            // 
            labelSM4PlaintextFormat.AutoSize = true;
            labelSM4PlaintextFormat.Location = new Point(534, 33);
            labelSM4PlaintextFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4PlaintextFormat.Name = "labelSM4PlaintextFormat";
            labelSM4PlaintextFormat.Size = new Size(73, 20);
            labelSM4PlaintextFormat.TabIndex = 11;
            labelSM4PlaintextFormat.Text = "明文格式:";
            // 
            // comboSM4PlaintextFormat
            // 
            comboSM4PlaintextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4PlaintextFormat.FormattingEnabled = true;
            comboSM4PlaintextFormat.Items.AddRange(new object[] { "Text", "Base64", "Hex" });
            comboSM4PlaintextFormat.Location = new Point(617, 29);
            comboSM4PlaintextFormat.Margin = new Padding(4);
            comboSM4PlaintextFormat.Name = "comboSM4PlaintextFormat";
            comboSM4PlaintextFormat.Size = new Size(127, 28);
            comboSM4PlaintextFormat.TabIndex = 10;
            // 
            // label15
            // 
            label15.AutoSize = true;
            label15.Location = new Point(276, 33);
            label15.Margin = new Padding(4, 0, 4, 0);
            label15.Name = "label15";
            label15.Size = new Size(73, 20);
            label15.TabIndex = 9;
            label15.Text = "填充模式:";
            // 
            // comboSM4Padding
            // 
            comboSM4Padding.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4Padding.FormattingEnabled = true;
            comboSM4Padding.Items.AddRange(new object[] { "PKCS7", "PKCS5", "NoPadding" });
            comboSM4Padding.Location = new Point(360, 29);
            comboSM4Padding.Margin = new Padding(4);
            comboSM4Padding.Name = "comboSM4Padding";
            comboSM4Padding.Size = new Size(127, 28);
            comboSM4Padding.TabIndex = 8;
            // 
            // label14
            // 
            label14.AutoSize = true;
            label14.Location = new Point(19, 33);
            label14.Margin = new Padding(4, 0, 4, 0);
            label14.Name = "label14";
            label14.Size = new Size(73, 20);
            label14.TabIndex = 7;
            label14.Text = "加密模式:";
            // 
            // comboSM4Mode
            // 
            comboSM4Mode.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4Mode.FormattingEnabled = true;
            comboSM4Mode.Items.AddRange(new object[] { "ECB", "CBC" });
            comboSM4Mode.Location = new Point(103, 29);
            comboSM4Mode.Margin = new Padding(4);
            comboSM4Mode.Name = "comboSM4Mode";
            comboSM4Mode.Size = new Size(127, 28);
            comboSM4Mode.TabIndex = 6;
            comboSM4Mode.SelectedIndexChanged += comboSM4Mode_SelectedIndexChanged;
            // 
            // label13
            // 
            label13.AutoSize = true;
            label13.Location = new Point(19, 186);
            label13.Margin = new Padding(4, 0, 4, 0);
            label13.Name = "label13";
            label13.Size = new Size(43, 20);
            label13.TabIndex = 5;
            label13.Text = "密文:";
            // 
            // textSM4CipherText
            // 
            textSM4CipherText.Location = new Point(103, 182);
            textSM4CipherText.Margin = new Padding(4);
            textSM4CipherText.Multiline = true;
            textSM4CipherText.Name = "textSM4CipherText";
            textSM4CipherText.ScrollBars = ScrollBars.Both;
            textSM4CipherText.Size = new Size(1137, 58);
            textSM4CipherText.TabIndex = 4;
            // 
            // label12
            // 
            label12.AutoSize = true;
            label12.Location = new Point(19, 115);
            label12.Margin = new Padding(4, 0, 4, 0);
            label12.Name = "label12";
            label12.Size = new Size(43, 20);
            label12.TabIndex = 3;
            label12.Text = "明文:";
            // 
            // textSM4PlainText
            // 
            textSM4PlainText.Location = new Point(103, 112);
            textSM4PlainText.Margin = new Padding(4);
            textSM4PlainText.Multiline = true;
            textSM4PlainText.Name = "textSM4PlainText";
            textSM4PlainText.ScrollBars = ScrollBars.Both;
            textSM4PlainText.Size = new Size(1137, 58);
            textSM4PlainText.TabIndex = 2;
            // 
            // btnSM4Decrypt
            // 
            btnSM4Decrypt.Location = new Point(884, 29);
            btnSM4Decrypt.Margin = new Padding(4);
            btnSM4Decrypt.Name = "btnSM4Decrypt";
            btnSM4Decrypt.Size = new Size(103, 28);
            btnSM4Decrypt.TabIndex = 1;
            btnSM4Decrypt.Text = "解密";
            btnSM4Decrypt.UseVisualStyleBackColor = true;
            btnSM4Decrypt.Click += btnSM4Decrypt_Click;
            // 
            // btnSM4Encrypt
            // 
            btnSM4Encrypt.Location = new Point(757, 29);
            btnSM4Encrypt.Margin = new Padding(4);
            btnSM4Encrypt.Name = "btnSM4Encrypt";
            btnSM4Encrypt.Size = new Size(103, 28);
            btnSM4Encrypt.TabIndex = 0;
            btnSM4Encrypt.Text = "加密";
            btnSM4Encrypt.UseVisualStyleBackColor = true;
            btnSM4Encrypt.Click += btnSM4Encrypt_Click;
            // 
            // groupBoxSM4Keys
            // 
            groupBoxSM4Keys.Controls.Add(btnExportSM4Key);
            groupBoxSM4Keys.Controls.Add(btnImportSM4Key);
            groupBoxSM4Keys.Controls.Add(labelSM4IVFormat);
            groupBoxSM4Keys.Controls.Add(comboSM4IVFormat);
            groupBoxSM4Keys.Controls.Add(labelSM4KeyFormat);
            groupBoxSM4Keys.Controls.Add(comboSM4KeyFormat);
            groupBoxSM4Keys.Controls.Add(label11);
            groupBoxSM4Keys.Controls.Add(textSM4IV);
            groupBoxSM4Keys.Controls.Add(label10);
            groupBoxSM4Keys.Controls.Add(textSM4Key);
            groupBoxSM4Keys.Controls.Add(btnGenerateSM4IV);
            groupBoxSM4Keys.Controls.Add(btnGenerateSM4Key);
            groupBoxSM4Keys.Location = new Point(8, 7);
            groupBoxSM4Keys.Margin = new Padding(4);
            groupBoxSM4Keys.Name = "groupBoxSM4Keys";
            groupBoxSM4Keys.Padding = new Padding(4);
            groupBoxSM4Keys.Size = new Size(1260, 212);
            groupBoxSM4Keys.TabIndex = 0;
            groupBoxSM4Keys.TabStop = false;
            groupBoxSM4Keys.Text = "SM4密钥生成";
            // 
            // btnExportSM4Key
            // 
            btnExportSM4Key.Location = new Point(967, 149);
            btnExportSM4Key.Margin = new Padding(4);
            btnExportSM4Key.Name = "btnExportSM4Key";
            btnExportSM4Key.Size = new Size(103, 28);
            btnExportSM4Key.TabIndex = 13;
            btnExportSM4Key.Text = "导出密钥";
            btnExportSM4Key.UseVisualStyleBackColor = true;
            btnExportSM4Key.Click += btnExportSM4Key_Click;
            // 
            // btnImportSM4Key
            // 
            btnImportSM4Key.Location = new Point(836, 149);
            btnImportSM4Key.Margin = new Padding(4);
            btnImportSM4Key.Name = "btnImportSM4Key";
            btnImportSM4Key.Size = new Size(103, 28);
            btnImportSM4Key.TabIndex = 12;
            btnImportSM4Key.Text = "导入密钥";
            btnImportSM4Key.UseVisualStyleBackColor = true;
            btnImportSM4Key.Click += btnImportSM4Key_Click;
            // 
            // labelSM4IVFormat
            // 
            labelSM4IVFormat.AutoSize = true;
            labelSM4IVFormat.Location = new Point(752, 104);
            labelSM4IVFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4IVFormat.Name = "labelSM4IVFormat";
            labelSM4IVFormat.Size = new Size(73, 20);
            labelSM4IVFormat.TabIndex = 11;
            labelSM4IVFormat.Text = "向量格式:";
            // 
            // comboSM4IVFormat
            // 
            comboSM4IVFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4IVFormat.FormattingEnabled = true;
            comboSM4IVFormat.Items.AddRange(new object[] { "Base64", "Hex", "Text" });
            comboSM4IVFormat.Location = new Point(836, 100);
            comboSM4IVFormat.Margin = new Padding(4);
            comboSM4IVFormat.Name = "comboSM4IVFormat";
            comboSM4IVFormat.Size = new Size(102, 28);
            comboSM4IVFormat.TabIndex = 10;
            comboSM4IVFormat.SelectedIndexChanged += comboSM4IVFormat_SelectedIndexChanged;
            // 
            // labelSM4KeyFormat
            // 
            labelSM4KeyFormat.AutoSize = true;
            labelSM4KeyFormat.Location = new Point(752, 45);
            labelSM4KeyFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4KeyFormat.Name = "labelSM4KeyFormat";
            labelSM4KeyFormat.Size = new Size(73, 20);
            labelSM4KeyFormat.TabIndex = 9;
            labelSM4KeyFormat.Text = "密钥格式:";
            // 
            // comboSM4KeyFormat
            // 
            comboSM4KeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4KeyFormat.FormattingEnabled = true;
            comboSM4KeyFormat.Items.AddRange(new object[] { "Base64", "Hex", "Text" });
            comboSM4KeyFormat.Location = new Point(836, 41);
            comboSM4KeyFormat.Margin = new Padding(4);
            comboSM4KeyFormat.Name = "comboSM4KeyFormat";
            comboSM4KeyFormat.Size = new Size(102, 28);
            comboSM4KeyFormat.TabIndex = 8;
            comboSM4KeyFormat.SelectedIndexChanged += comboSM4KeyFormat_SelectedIndexChanged;
            // 
            // label11
            // 
            label11.AutoSize = true;
            label11.Location = new Point(19, 104);
            label11.Margin = new Padding(4, 0, 4, 0);
            label11.Name = "label11";
            label11.Size = new Size(73, 20);
            label11.TabIndex = 5;
            label11.Text = "初始向量:";
            // 
            // textSM4IV
            // 
            textSM4IV.Location = new Point(103, 100);
            textSM4IV.Margin = new Padding(4);
            textSM4IV.Name = "textSM4IV";
            textSM4IV.Size = new Size(642, 27);
            textSM4IV.TabIndex = 4;
            // 
            // label10
            // 
            label10.AutoSize = true;
            label10.Location = new Point(19, 45);
            label10.Margin = new Padding(4, 0, 4, 0);
            label10.Name = "label10";
            label10.Size = new Size(76, 20);
            label10.TabIndex = 3;
            label10.Text = "SM4密钥:";
            // 
            // textSM4Key
            // 
            textSM4Key.Location = new Point(103, 41);
            textSM4Key.Margin = new Padding(4);
            textSM4Key.Name = "textSM4Key";
            textSM4Key.Size = new Size(642, 27);
            textSM4Key.TabIndex = 2;
            textSM4Key.TextChanged += textSM4Key_TextChanged;
            // 
            // btnGenerateSM4IV
            // 
            btnGenerateSM4IV.Location = new Point(967, 100);
            btnGenerateSM4IV.Margin = new Padding(4);
            btnGenerateSM4IV.Name = "btnGenerateSM4IV";
            btnGenerateSM4IV.Size = new Size(103, 28);
            btnGenerateSM4IV.TabIndex = 1;
            btnGenerateSM4IV.Text = "生成向量";
            btnGenerateSM4IV.UseVisualStyleBackColor = true;
            btnGenerateSM4IV.Click += btnGenerateSM4IV_Click;
            // 
            // btnGenerateSM4Key
            // 
            btnGenerateSM4Key.Location = new Point(967, 41);
            btnGenerateSM4Key.Margin = new Padding(4);
            btnGenerateSM4Key.Name = "btnGenerateSM4Key";
            btnGenerateSM4Key.Size = new Size(103, 28);
            btnGenerateSM4Key.TabIndex = 0;
            btnGenerateSM4Key.Text = "生成密钥";
            btnGenerateSM4Key.UseVisualStyleBackColor = true;
            btnGenerateSM4Key.Click += btnGenerateSM4Key_Click;
            // 
            // tabSM2
            // 
            tabSM2.Controls.Add(groupBoxSM2Sign);
            tabSM2.Controls.Add(groupBoxSM2Encrypt);
            tabSM2.Controls.Add(groupBoxSM2Keys);
            tabSM2.Location = new Point(4, 29);
            tabSM2.Margin = new Padding(4);
            tabSM2.Name = "tabSM2";
            tabSM2.Padding = new Padding(4);
            tabSM2.Size = new Size(1278, 732);
            tabSM2.TabIndex = 2;
            tabSM2.Text = "SM2算法";
            tabSM2.UseVisualStyleBackColor = true;
            // 
            // groupBoxSM2Sign
            // 
            groupBoxSM2Sign.Controls.Add(labelSM2VerifyResult);
            groupBoxSM2Sign.Controls.Add(label24);
            groupBoxSM2Sign.Controls.Add(textSM2Signature);
            groupBoxSM2Sign.Controls.Add(label23);
            groupBoxSM2Sign.Controls.Add(textSM2SignData);
            groupBoxSM2Sign.Controls.Add(btnSM2Verify);
            groupBoxSM2Sign.Controls.Add(btnSM2Sign);
            groupBoxSM2Sign.Controls.Add(label22);
            groupBoxSM2Sign.Controls.Add(comboSM2SignFormat);
            groupBoxSM2Sign.Location = new Point(8, 468);
            groupBoxSM2Sign.Margin = new Padding(4);
            groupBoxSM2Sign.Name = "groupBoxSM2Sign";
            groupBoxSM2Sign.Padding = new Padding(4);
            groupBoxSM2Sign.Size = new Size(1260, 256);
            groupBoxSM2Sign.TabIndex = 2;
            groupBoxSM2Sign.TabStop = false;
            groupBoxSM2Sign.Text = "SM2数字签名";
            // 
            // labelSM2VerifyResult
            // 
            labelSM2VerifyResult.AutoSize = true;
            labelSM2VerifyResult.Location = new Point(514, 214);
            labelSM2VerifyResult.Margin = new Padding(4, 0, 4, 0);
            labelSM2VerifyResult.Name = "labelSM2VerifyResult";
            labelSM2VerifyResult.Size = new Size(73, 20);
            labelSM2VerifyResult.TabIndex = 8;
            labelSM2VerifyResult.Text = "验签结果:";
            // 
            // label24
            // 
            label24.AutoSize = true;
            label24.Location = new Point(19, 145);
            label24.Margin = new Padding(4, 0, 4, 0);
            label24.Name = "label24";
            label24.Size = new Size(43, 20);
            label24.TabIndex = 7;
            label24.Text = "签名:";
            // 
            // textSM2Signature
            // 
            textSM2Signature.Location = new Point(103, 141);
            textSM2Signature.Margin = new Padding(4);
            textSM2Signature.Multiline = true;
            textSM2Signature.Name = "textSM2Signature";
            textSM2Signature.ScrollBars = ScrollBars.Both;
            textSM2Signature.Size = new Size(1137, 58);
            textSM2Signature.TabIndex = 6;
            // 
            // label23
            // 
            label23.AutoSize = true;
            label23.Location = new Point(19, 74);
            label23.Margin = new Padding(4, 0, 4, 0);
            label23.Name = "label23";
            label23.Size = new Size(73, 20);
            label23.TabIndex = 5;
            label23.Text = "原文数据:";
            // 
            // textSM2SignData
            // 
            textSM2SignData.Location = new Point(103, 71);
            textSM2SignData.Margin = new Padding(4);
            textSM2SignData.Multiline = true;
            textSM2SignData.Name = "textSM2SignData";
            textSM2SignData.ScrollBars = ScrollBars.Both;
            textSM2SignData.Size = new Size(1137, 58);
            textSM2SignData.TabIndex = 4;
            // 
            // btnSM2Verify
            // 
            btnSM2Verify.Location = new Point(514, 29);
            btnSM2Verify.Margin = new Padding(4);
            btnSM2Verify.Name = "btnSM2Verify";
            btnSM2Verify.Size = new Size(103, 28);
            btnSM2Verify.TabIndex = 3;
            btnSM2Verify.Text = "验签";
            btnSM2Verify.UseVisualStyleBackColor = true;
            btnSM2Verify.Click += btnSM2Verify_Click;
            // 
            // btnSM2Sign
            // 
            btnSM2Sign.Location = new Point(360, 29);
            btnSM2Sign.Margin = new Padding(4);
            btnSM2Sign.Name = "btnSM2Sign";
            btnSM2Sign.Size = new Size(103, 28);
            btnSM2Sign.TabIndex = 2;
            btnSM2Sign.Text = "签名";
            btnSM2Sign.UseVisualStyleBackColor = true;
            btnSM2Sign.Click += btnSM2Sign_Click;
            // 
            // label22
            // 
            label22.AutoSize = true;
            label22.Location = new Point(19, 33);
            label22.Margin = new Padding(4, 0, 4, 0);
            label22.Name = "label22";
            label22.Size = new Size(73, 20);
            label22.TabIndex = 1;
            label22.Text = "签名格式:";
            // 
            // comboSM2SignFormat
            // 
            comboSM2SignFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2SignFormat.FormattingEnabled = true;
            comboSM2SignFormat.Items.AddRange(new object[] { "ASN1", "RS" });
            comboSM2SignFormat.Location = new Point(103, 29);
            comboSM2SignFormat.Margin = new Padding(4);
            comboSM2SignFormat.Name = "comboSM2SignFormat";
            comboSM2SignFormat.Size = new Size(127, 28);
            comboSM2SignFormat.TabIndex = 0;
            // 
            // groupBoxSM2Encrypt
            // 
            groupBoxSM2Encrypt.Controls.Add(label21);
            groupBoxSM2Encrypt.Controls.Add(textSM2CipherText);
            groupBoxSM2Encrypt.Controls.Add(label20);
            groupBoxSM2Encrypt.Controls.Add(textSM2PlainText);
            groupBoxSM2Encrypt.Controls.Add(btnSM2Decrypt);
            groupBoxSM2Encrypt.Controls.Add(btnSM2Encrypt);
            groupBoxSM2Encrypt.Controls.Add(label19);
            groupBoxSM2Encrypt.Controls.Add(comboSM2CipherFormat);
            groupBoxSM2Encrypt.Location = new Point(8, 249);
            groupBoxSM2Encrypt.Margin = new Padding(4);
            groupBoxSM2Encrypt.Name = "groupBoxSM2Encrypt";
            groupBoxSM2Encrypt.Padding = new Padding(4);
            groupBoxSM2Encrypt.Size = new Size(1260, 212);
            groupBoxSM2Encrypt.TabIndex = 1;
            groupBoxSM2Encrypt.TabStop = false;
            groupBoxSM2Encrypt.Text = "SM2加密解密";
            // 
            // label21
            // 
            label21.AutoSize = true;
            label21.Location = new Point(19, 127);
            label21.Margin = new Padding(4, 0, 4, 0);
            label21.Name = "label21";
            label21.Size = new Size(43, 20);
            label21.TabIndex = 7;
            label21.Text = "密文:";
            // 
            // textSM2CipherText
            // 
            textSM2CipherText.Location = new Point(103, 124);
            textSM2CipherText.Margin = new Padding(4);
            textSM2CipherText.Multiline = true;
            textSM2CipherText.Name = "textSM2CipherText";
            textSM2CipherText.ScrollBars = ScrollBars.Both;
            textSM2CipherText.Size = new Size(1137, 40);
            textSM2CipherText.TabIndex = 6;
            // 
            // label20
            // 
            label20.AutoSize = true;
            label20.Location = new Point(19, 74);
            label20.Margin = new Padding(4, 0, 4, 0);
            label20.Name = "label20";
            label20.Size = new Size(43, 20);
            label20.TabIndex = 5;
            label20.Text = "明文:";
            // 
            // textSM2PlainText
            // 
            textSM2PlainText.Location = new Point(103, 71);
            textSM2PlainText.Margin = new Padding(4);
            textSM2PlainText.Multiline = true;
            textSM2PlainText.Name = "textSM2PlainText";
            textSM2PlainText.ScrollBars = ScrollBars.Both;
            textSM2PlainText.Size = new Size(1137, 40);
            textSM2PlainText.TabIndex = 4;
            // 
            // btnSM2Decrypt
            // 
            btnSM2Decrypt.Location = new Point(514, 29);
            btnSM2Decrypt.Margin = new Padding(4);
            btnSM2Decrypt.Name = "btnSM2Decrypt";
            btnSM2Decrypt.Size = new Size(103, 28);
            btnSM2Decrypt.TabIndex = 3;
            btnSM2Decrypt.Text = "解密";
            btnSM2Decrypt.UseVisualStyleBackColor = true;
            btnSM2Decrypt.Click += btnSM2Decrypt_Click;
            // 
            // btnSM2Encrypt
            // 
            btnSM2Encrypt.Location = new Point(360, 29);
            btnSM2Encrypt.Margin = new Padding(4);
            btnSM2Encrypt.Name = "btnSM2Encrypt";
            btnSM2Encrypt.Size = new Size(103, 28);
            btnSM2Encrypt.TabIndex = 2;
            btnSM2Encrypt.Text = "加密";
            btnSM2Encrypt.UseVisualStyleBackColor = true;
            btnSM2Encrypt.Click += btnSM2Encrypt_Click;
            // 
            // label19
            // 
            label19.AutoSize = true;
            label19.Location = new Point(19, 33);
            label19.Margin = new Padding(4, 0, 4, 0);
            label19.Name = "label19";
            label19.Size = new Size(73, 20);
            label19.TabIndex = 1;
            label19.Text = "密文格式:";
            // 
            // comboSM2CipherFormat
            // 
            comboSM2CipherFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2CipherFormat.FormattingEnabled = true;
            comboSM2CipherFormat.Items.AddRange(new object[] { "C1C3C2", "C1C2C3", "ASN1" });
            comboSM2CipherFormat.Location = new Point(103, 29);
            comboSM2CipherFormat.Margin = new Padding(4);
            comboSM2CipherFormat.Name = "comboSM2CipherFormat";
            comboSM2CipherFormat.Size = new Size(127, 28);
            comboSM2CipherFormat.TabIndex = 0;
            // 
            // groupBoxSM2Keys
            // 
            groupBoxSM2Keys.Controls.Add(btnExportSM2Key);
            groupBoxSM2Keys.Controls.Add(btnImportSM2Key);
            groupBoxSM2Keys.Controls.Add(label18);
            groupBoxSM2Keys.Controls.Add(textSM2PrivateKey);
            groupBoxSM2Keys.Controls.Add(label17);
            groupBoxSM2Keys.Controls.Add(textSM2PublicKey);
            groupBoxSM2Keys.Controls.Add(label16);
            groupBoxSM2Keys.Controls.Add(comboSM2KeyFormat);
            groupBoxSM2Keys.Controls.Add(btnGenerateSM2Key);
            groupBoxSM2Keys.Location = new Point(8, 7);
            groupBoxSM2Keys.Margin = new Padding(4);
            groupBoxSM2Keys.Name = "groupBoxSM2Keys";
            groupBoxSM2Keys.Padding = new Padding(4);
            groupBoxSM2Keys.Size = new Size(1260, 235);
            groupBoxSM2Keys.TabIndex = 0;
            groupBoxSM2Keys.TabStop = false;
            groupBoxSM2Keys.Text = "SM2密钥生成";
            // 
            // btnExportSM2Key
            // 
            btnExportSM2Key.Location = new Point(643, 29);
            btnExportSM2Key.Margin = new Padding(4);
            btnExportSM2Key.Name = "btnExportSM2Key";
            btnExportSM2Key.Size = new Size(103, 28);
            btnExportSM2Key.TabIndex = 8;
            btnExportSM2Key.Text = "导出密钥";
            btnExportSM2Key.UseVisualStyleBackColor = true;
            btnExportSM2Key.Click += btnExportSM2Key_Click;
            // 
            // btnImportSM2Key
            // 
            btnImportSM2Key.Location = new Point(514, 29);
            btnImportSM2Key.Margin = new Padding(4);
            btnImportSM2Key.Name = "btnImportSM2Key";
            btnImportSM2Key.Size = new Size(103, 28);
            btnImportSM2Key.TabIndex = 7;
            btnImportSM2Key.Text = "导入密钥";
            btnImportSM2Key.UseVisualStyleBackColor = true;
            btnImportSM2Key.Click += btnImportSM2Key_Click;
            // 
            // label18
            // 
            label18.AutoSize = true;
            label18.Location = new Point(19, 162);
            label18.Margin = new Padding(4, 0, 4, 0);
            label18.Name = "label18";
            label18.Size = new Size(43, 20);
            label18.TabIndex = 6;
            label18.Text = "私钥:";
            // 
            // textSM2PrivateKey
            // 
            textSM2PrivateKey.Location = new Point(103, 159);
            textSM2PrivateKey.Margin = new Padding(4);
            textSM2PrivateKey.Multiline = true;
            textSM2PrivateKey.Name = "textSM2PrivateKey";
            textSM2PrivateKey.ScrollBars = ScrollBars.Both;
            textSM2PrivateKey.Size = new Size(1137, 70);
            textSM2PrivateKey.TabIndex = 5;
            // 
            // label17
            // 
            label17.AutoSize = true;
            label17.Location = new Point(19, 80);
            label17.Margin = new Padding(4, 0, 4, 0);
            label17.Name = "label17";
            label17.Size = new Size(43, 20);
            label17.TabIndex = 4;
            label17.Text = "公钥:";
            // 
            // textSM2PublicKey
            // 
            textSM2PublicKey.Location = new Point(103, 76);
            textSM2PublicKey.Margin = new Padding(4);
            textSM2PublicKey.Multiline = true;
            textSM2PublicKey.Name = "textSM2PublicKey";
            textSM2PublicKey.ScrollBars = ScrollBars.Both;
            textSM2PublicKey.Size = new Size(1137, 70);
            textSM2PublicKey.TabIndex = 3;
            // 
            // label16
            // 
            label16.AutoSize = true;
            label16.Location = new Point(19, 33);
            label16.Margin = new Padding(4, 0, 4, 0);
            label16.Name = "label16";
            label16.Size = new Size(73, 20);
            label16.TabIndex = 2;
            label16.Text = "密钥格式:";
            // 
            // comboSM2KeyFormat
            // 
            comboSM2KeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM2KeyFormat.FormattingEnabled = true;
            comboSM2KeyFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboSM2KeyFormat.Location = new Point(103, 29);
            comboSM2KeyFormat.Margin = new Padding(4);
            comboSM2KeyFormat.Name = "comboSM2KeyFormat";
            comboSM2KeyFormat.Size = new Size(127, 28);
            comboSM2KeyFormat.TabIndex = 1;
            // 
            // btnGenerateSM2Key
            // 
            btnGenerateSM2Key.Location = new Point(360, 29);
            btnGenerateSM2Key.Margin = new Padding(4);
            btnGenerateSM2Key.Name = "btnGenerateSM2Key";
            btnGenerateSM2Key.Size = new Size(129, 28);
            btnGenerateSM2Key.TabIndex = 0;
            btnGenerateSM2Key.Text = "生成密钥对";
            btnGenerateSM2Key.UseVisualStyleBackColor = true;
            btnGenerateSM2Key.Click += btnGenerateSM2Key_Click;
            // 
            // statusStrip1
            // 
            statusStrip1.ImageScalingSize = new Size(20, 20);
            statusStrip1.Items.AddRange(new ToolStripItem[] { toolStripStatusLabel1 });
            statusStrip1.Location = new Point(0, 739);
            statusStrip1.Name = "statusStrip1";
            statusStrip1.Padding = new Padding(1, 0, 18, 0);
            statusStrip1.Size = new Size(1286, 26);
            statusStrip1.TabIndex = 1;
            statusStrip1.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            toolStripStatusLabel1.Size = new Size(39, 20);
            toolStripStatusLabel1.Text = "就绪";
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1286, 765);
            Controls.Add(statusStrip1);
            Controls.Add(tabControl1);
            Margin = new Padding(4);
            Name = "Form1";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "加密工具 - RSA & SM4 & SM2";
            Load += Form1_Load;
            tabControl1.ResumeLayout(false);
            tabRSA.ResumeLayout(false);
            groupBoxRSASign.ResumeLayout(false);
            groupBoxRSASign.PerformLayout();
            groupBoxRSAEncrypt.ResumeLayout(false);
            groupBoxRSAEncrypt.PerformLayout();
            groupBoxRSAKeys.ResumeLayout(false);
            groupBoxRSAKeys.PerformLayout();
            tabSM4.ResumeLayout(false);
            groupBoxSM4Encrypt.ResumeLayout(false);
            groupBoxSM4Encrypt.PerformLayout();
            groupBoxSM4Keys.ResumeLayout(false);
            groupBoxSM4Keys.PerformLayout();
            tabSM2.ResumeLayout(false);
            groupBoxSM2Sign.ResumeLayout(false);
            groupBoxSM2Sign.PerformLayout();
            groupBoxSM2Encrypt.ResumeLayout(false);
            groupBoxSM2Encrypt.PerformLayout();
            groupBoxSM2Keys.ResumeLayout(false);
            groupBoxSM2Keys.PerformLayout();
            statusStrip1.ResumeLayout(false);
            statusStrip1.PerformLayout();
            ResumeLayout(false);
            PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabRSA;
        private System.Windows.Forms.GroupBox groupBoxRSAKeys;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox textRSAPrivateKey;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox textRSAPublicKey;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ComboBox comboRSAKeyFormat;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.ComboBox comboRSAKeySize;
        private System.Windows.Forms.Button btnGenerateRSAKey;
        private System.Windows.Forms.Button btnImportRSAKey;
        private System.Windows.Forms.Button btnExportRSAKey;
        private System.Windows.Forms.GroupBox groupBoxRSASign;
        private System.Windows.Forms.Label labelRSAVerifyResult;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.ComboBox comboRSAType;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.TextBox textRSASignature;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.TextBox textRSASignData;
        private System.Windows.Forms.Button btnRSAVerify;
        private System.Windows.Forms.Button btnRSASign;
        private System.Windows.Forms.GroupBox groupBoxRSAEncrypt;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.TextBox textRSACipherText;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TextBox textRSAPlainText;
        private System.Windows.Forms.Button btnRSADecrypt;
        private System.Windows.Forms.Button btnRSAEncrypt;
        private System.Windows.Forms.TabPage tabSM4;
        private System.Windows.Forms.GroupBox groupBoxSM4Encrypt;
        private System.Windows.Forms.Label labelSM4DataFormat;
        private System.Windows.Forms.ComboBox comboSM4DataFormat;
        private System.Windows.Forms.Label labelSM4PlaintextFormat;
        private System.Windows.Forms.ComboBox comboSM4PlaintextFormat;
        private System.Windows.Forms.Label labelSM4CiphertextFormat;
        private System.Windows.Forms.ComboBox comboSM4CiphertextFormat;
        private System.Windows.Forms.Label label15;
        private System.Windows.Forms.ComboBox comboSM4Padding;
        private System.Windows.Forms.Label label14;
        private System.Windows.Forms.ComboBox comboSM4Mode;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.TextBox textSM4CipherText;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.TextBox textSM4PlainText;
        private System.Windows.Forms.Button btnSM4Decrypt;
        private System.Windows.Forms.Button btnSM4Encrypt;
        private System.Windows.Forms.GroupBox groupBoxSM4Keys;
        private System.Windows.Forms.Button btnExportSM4Key;
        private System.Windows.Forms.Button btnImportSM4Key;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.TextBox textSM4IV;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.TextBox textSM4Key;
        private System.Windows.Forms.Button btnGenerateSM4IV;
        private System.Windows.Forms.Button btnGenerateSM4Key;
        private System.Windows.Forms.ComboBox comboSM4KeyFormat;
        private System.Windows.Forms.Label labelSM4KeyFormat;
        private System.Windows.Forms.ComboBox comboSM4IVFormat;
        private System.Windows.Forms.Label labelSM4IVFormat;
        private System.Windows.Forms.TabPage tabSM2;
        private System.Windows.Forms.GroupBox groupBoxSM2Keys;
        private System.Windows.Forms.Button btnExportSM2Key;
        private System.Windows.Forms.Button btnImportSM2Key;
        private System.Windows.Forms.Label label18;
        private System.Windows.Forms.TextBox textSM2PrivateKey;
        private System.Windows.Forms.Label label17;
        private System.Windows.Forms.TextBox textSM2PublicKey;
        private System.Windows.Forms.Label label16;
        private System.Windows.Forms.ComboBox comboSM2KeyFormat;
        private System.Windows.Forms.Button btnGenerateSM2Key;
        private System.Windows.Forms.GroupBox groupBoxSM2Encrypt;
        private System.Windows.Forms.Label label21;
        private System.Windows.Forms.TextBox textSM2CipherText;
        private System.Windows.Forms.Label label20;
        private System.Windows.Forms.TextBox textSM2PlainText;
        private System.Windows.Forms.Button btnSM2Decrypt;
        private System.Windows.Forms.Button btnSM2Encrypt;
        private System.Windows.Forms.Label label19;
        private System.Windows.Forms.ComboBox comboSM2CipherFormat;
        private System.Windows.Forms.GroupBox groupBoxSM2Sign;
        private System.Windows.Forms.Label labelSM2VerifyResult;
        private System.Windows.Forms.Label label24;
        private System.Windows.Forms.TextBox textSM2Signature;
        private System.Windows.Forms.Label label23;
        private System.Windows.Forms.TextBox textSM2SignData;
        private System.Windows.Forms.Button btnSM2Verify;
        private System.Windows.Forms.Button btnSM2Sign;
        private System.Windows.Forms.Label label22;
        private System.Windows.Forms.ComboBox comboSM2SignFormat;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
    }
}
