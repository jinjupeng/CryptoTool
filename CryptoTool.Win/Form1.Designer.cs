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
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabRSA = new System.Windows.Forms.TabPage();
            this.groupBoxRSAKeys = new System.Windows.Forms.GroupBox();
            this.btnGenerateRSAKey = new System.Windows.Forms.Button();
            this.comboRSAKeySize = new System.Windows.Forms.ComboBox();
            this.label1 = new System.Windows.Forms.Label();
            this.comboRSAKeyFormat = new System.Windows.Forms.ComboBox();
            this.label2 = new System.Windows.Forms.Label();
            this.textRSAPublicKey = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.textRSAPrivateKey = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.groupBoxRSAEncrypt = new System.Windows.Forms.GroupBox();
            this.btnRSAEncrypt = new System.Windows.Forms.Button();
            this.btnRSADecrypt = new System.Windows.Forms.Button();
            this.textRSAPlainText = new System.Windows.Forms.TextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.textRSACipherText = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.groupBoxRSASign = new System.Windows.Forms.GroupBox();
            this.btnRSASign = new System.Windows.Forms.Button();
            this.btnRSAVerify = new System.Windows.Forms.Button();
            this.textRSASignData = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.textRSASignature = new System.Windows.Forms.TextBox();
            this.label8 = new System.Windows.Forms.Label();
            this.comboRSAType = new System.Windows.Forms.ComboBox();
            this.label9 = new System.Windows.Forms.Label();
            this.labelRSAVerifyResult = new System.Windows.Forms.Label();
            this.tabSM4 = new System.Windows.Forms.TabPage();
            this.groupBoxSM4Keys = new System.Windows.Forms.GroupBox();
            this.btnGenerateSM4Key = new System.Windows.Forms.Button();
            this.btnGenerateSM4IV = new System.Windows.Forms.Button();
            this.textSM4Key = new System.Windows.Forms.TextBox();
            this.label10 = new System.Windows.Forms.Label();
            this.textSM4IV = new System.Windows.Forms.TextBox();
            this.label11 = new System.Windows.Forms.Label();
            this.groupBoxSM4Encrypt = new System.Windows.Forms.GroupBox();
            this.btnSM4Encrypt = new System.Windows.Forms.Button();
            this.btnSM4Decrypt = new System.Windows.Forms.Button();
            this.textSM4PlainText = new System.Windows.Forms.TextBox();
            this.label12 = new System.Windows.Forms.Label();
            this.textSM4CipherText = new System.Windows.Forms.TextBox();
            this.label13 = new System.Windows.Forms.Label();
            this.comboSM4Mode = new System.Windows.Forms.ComboBox();
            this.label14 = new System.Windows.Forms.Label();
            this.comboSM4Padding = new System.Windows.Forms.ComboBox();
            this.label15 = new System.Windows.Forms.Label();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.toolStripStatusLabel1 = new System.Windows.Forms.ToolStripStatusLabel();
            this.tabControl1.SuspendLayout();
            this.tabRSA.SuspendLayout();
            this.groupBoxRSAKeys.SuspendLayout();
            this.groupBoxRSAEncrypt.SuspendLayout();
            this.groupBoxRSASign.SuspendLayout();
            this.tabSM4.SuspendLayout();
            this.groupBoxSM4Keys.SuspendLayout();
            this.groupBoxSM4Encrypt.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabRSA);
            this.tabControl1.Controls.Add(this.tabSM4);
            this.tabControl1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControl1.Location = new System.Drawing.Point(0, 0);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(1000, 650);
            this.tabControl1.TabIndex = 0;
            // 
            // tabRSA
            // 
            this.tabRSA.Controls.Add(this.groupBoxRSASign);
            this.tabRSA.Controls.Add(this.groupBoxRSAEncrypt);
            this.tabRSA.Controls.Add(this.groupBoxRSAKeys);
            this.tabRSA.Location = new System.Drawing.Point(4, 24);
            this.tabRSA.Name = "tabRSA";
            this.tabRSA.Padding = new System.Windows.Forms.Padding(3);
            this.tabRSA.Size = new System.Drawing.Size(992, 622);
            this.tabRSA.TabIndex = 0;
            this.tabRSA.Text = "RSA算法";
            this.tabRSA.UseVisualStyleBackColor = true;
            // 
            // groupBoxRSAKeys
            // 
            this.groupBoxRSAKeys.Controls.Add(this.label4);
            this.groupBoxRSAKeys.Controls.Add(this.textRSAPrivateKey);
            this.groupBoxRSAKeys.Controls.Add(this.label3);
            this.groupBoxRSAKeys.Controls.Add(this.textRSAPublicKey);
            this.groupBoxRSAKeys.Controls.Add(this.label2);
            this.groupBoxRSAKeys.Controls.Add(this.comboRSAKeyFormat);
            this.groupBoxRSAKeys.Controls.Add(this.label1);
            this.groupBoxRSAKeys.Controls.Add(this.comboRSAKeySize);
            this.groupBoxRSAKeys.Controls.Add(this.btnGenerateRSAKey);
            this.groupBoxRSAKeys.Location = new System.Drawing.Point(6, 6);
            this.groupBoxRSAKeys.Name = "groupBoxRSAKeys";
            this.groupBoxRSAKeys.Size = new System.Drawing.Size(980, 200);
            this.groupBoxRSAKeys.TabIndex = 0;
            this.groupBoxRSAKeys.TabStop = false;
            this.groupBoxRSAKeys.Text = "RSA密钥生成";
            // 
            // btnGenerateRSAKey
            // 
            this.btnGenerateRSAKey.Location = new System.Drawing.Point(380, 25);
            this.btnGenerateRSAKey.Name = "btnGenerateRSAKey";
            this.btnGenerateRSAKey.Size = new System.Drawing.Size(100, 30);
            this.btnGenerateRSAKey.TabIndex = 0;
            this.btnGenerateRSAKey.Text = "生成密钥对";
            this.btnGenerateRSAKey.UseVisualStyleBackColor = true;
            this.btnGenerateRSAKey.Click += new System.EventHandler(this.btnGenerateRSAKey_Click);
            // 
            // comboRSAKeySize
            // 
            this.comboRSAKeySize.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboRSAKeySize.FormattingEnabled = true;
            this.comboRSAKeySize.Items.AddRange(new object[] {
            "1024",
            "2048",
            "3072",
            "4096"});
            this.comboRSAKeySize.Location = new System.Drawing.Point(80, 25);
            this.comboRSAKeySize.Name = "comboRSAKeySize";
            this.comboRSAKeySize.Size = new System.Drawing.Size(100, 25);
            this.comboRSAKeySize.TabIndex = 1;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(15, 28);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(59, 17);
            this.label1.TabIndex = 2;
            this.label1.Text = "密钥长度:";
            // 
            // comboRSAKeyFormat
            // 
            this.comboRSAKeyFormat.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboRSAKeyFormat.FormattingEnabled = true;
            this.comboRSAKeyFormat.Items.AddRange(new object[] {
            "XML",
            "PKCS1",
            "PKCS8",
            "Java"});
            this.comboRSAKeyFormat.Location = new System.Drawing.Point(260, 25);
            this.comboRSAKeyFormat.Name = "comboRSAKeyFormat";
            this.comboRSAKeyFormat.Size = new System.Drawing.Size(100, 25);
            this.comboRSAKeyFormat.TabIndex = 3;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(195, 28);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(59, 17);
            this.label2.TabIndex = 4;
            this.label2.Text = "密钥格式:";
            // 
            // textRSAPublicKey
            // 
            this.textRSAPublicKey.Location = new System.Drawing.Point(80, 65);
            this.textRSAPublicKey.Multiline = true;
            this.textRSAPublicKey.Name = "textRSAPublicKey";
            this.textRSAPublicKey.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textRSAPublicKey.Size = new System.Drawing.Size(885, 60);
            this.textRSAPublicKey.TabIndex = 5;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(15, 68);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(35, 17);
            this.label3.TabIndex = 6;
            this.label3.Text = "公钥:";
            // 
            // textRSAPrivateKey
            // 
            this.textRSAPrivateKey.Location = new System.Drawing.Point(80, 135);
            this.textRSAPrivateKey.Multiline = true;
            this.textRSAPrivateKey.Name = "textRSAPrivateKey";
            this.textRSAPrivateKey.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textRSAPrivateKey.Size = new System.Drawing.Size(885, 60);
            this.textRSAPrivateKey.TabIndex = 7;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(15, 138);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(35, 17);
            this.label4.TabIndex = 8;
            this.label4.Text = "私钥:";
            // 
            // groupBoxRSAEncrypt
            // 
            this.groupBoxRSAEncrypt.Controls.Add(this.label6);
            this.groupBoxRSAEncrypt.Controls.Add(this.textRSACipherText);
            this.groupBoxRSAEncrypt.Controls.Add(this.label5);
            this.groupBoxRSAEncrypt.Controls.Add(this.textRSAPlainText);
            this.groupBoxRSAEncrypt.Controls.Add(this.btnRSADecrypt);
            this.groupBoxRSAEncrypt.Controls.Add(this.btnRSAEncrypt);
            this.groupBoxRSAEncrypt.Location = new System.Drawing.Point(6, 212);
            this.groupBoxRSAEncrypt.Name = "groupBoxRSAEncrypt";
            this.groupBoxRSAEncrypt.Size = new System.Drawing.Size(980, 180);
            this.groupBoxRSAEncrypt.TabIndex = 1;
            this.groupBoxRSAEncrypt.TabStop = false;
            this.groupBoxRSAEncrypt.Text = "RSA加密解密";
            // 
            // btnRSAEncrypt
            // 
            this.btnRSAEncrypt.Location = new System.Drawing.Point(200, 140);
            this.btnRSAEncrypt.Name = "btnRSAEncrypt";
            this.btnRSAEncrypt.Size = new System.Drawing.Size(80, 30);
            this.btnRSAEncrypt.TabIndex = 0;
            this.btnRSAEncrypt.Text = "加密";
            this.btnRSAEncrypt.UseVisualStyleBackColor = true;
            this.btnRSAEncrypt.Click += new System.EventHandler(this.btnRSAEncrypt_Click);
            // 
            // btnRSADecrypt
            // 
            this.btnRSADecrypt.Location = new System.Drawing.Point(300, 140);
            this.btnRSADecrypt.Name = "btnRSADecrypt";
            this.btnRSADecrypt.Size = new System.Drawing.Size(80, 30);
            this.btnRSADecrypt.TabIndex = 1;
            this.btnRSADecrypt.Text = "解密";
            this.btnRSADecrypt.UseVisualStyleBackColor = true;
            this.btnRSADecrypt.Click += new System.EventHandler(this.btnRSADecrypt_Click);
            // 
            // textRSAPlainText
            // 
            this.textRSAPlainText.Location = new System.Drawing.Point(80, 25);
            this.textRSAPlainText.Multiline = true;
            this.textRSAPlainText.Name = "textRSAPlainText";
            this.textRSAPlainText.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textRSAPlainText.Size = new System.Drawing.Size(885, 50);
            this.textRSAPlainText.TabIndex = 2;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(15, 28);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(35, 17);
            this.label5.TabIndex = 3;
            this.label5.Text = "明文:";
            // 
            // textRSACipherText
            // 
            this.textRSACipherText.Location = new System.Drawing.Point(80, 85);
            this.textRSACipherText.Multiline = true;
            this.textRSACipherText.Name = "textRSACipherText";
            this.textRSACipherText.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textRSACipherText.Size = new System.Drawing.Size(885, 50);
            this.textRSACipherText.TabIndex = 4;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(15, 88);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(35, 17);
            this.label6.TabIndex = 5;
            this.label6.Text = "密文:";
            // 
            // groupBoxRSASign
            // 
            this.groupBoxRSASign.Controls.Add(this.labelRSAVerifyResult);
            this.groupBoxRSASign.Controls.Add(this.label9);
            this.groupBoxRSASign.Controls.Add(this.comboRSAType);
            this.groupBoxRSASign.Controls.Add(this.label8);
            this.groupBoxRSASign.Controls.Add(this.textRSASignature);
            this.groupBoxRSASign.Controls.Add(this.label7);
            this.groupBoxRSASign.Controls.Add(this.textRSASignData);
            this.groupBoxRSASign.Controls.Add(this.btnRSAVerify);
            this.groupBoxRSASign.Controls.Add(this.btnRSASign);
            this.groupBoxRSASign.Location = new System.Drawing.Point(6, 398);
            this.groupBoxRSASign.Name = "groupBoxRSASign";
            this.groupBoxRSASign.Size = new System.Drawing.Size(980, 218);
            this.groupBoxRSASign.TabIndex = 2;
            this.groupBoxRSASign.TabStop = false;
            this.groupBoxRSASign.Text = "RSA数字签名";
            // 
            // btnRSASign
            // 
            this.btnRSASign.Location = new System.Drawing.Point(200, 175);
            this.btnRSASign.Name = "btnRSASign";
            this.btnRSASign.Size = new System.Drawing.Size(80, 30);
            this.btnRSASign.TabIndex = 0;
            this.btnRSASign.Text = "签名";
            this.btnRSASign.UseVisualStyleBackColor = true;
            this.btnRSASign.Click += new System.EventHandler(this.btnRSASign_Click);
            // 
            // btnRSAVerify
            // 
            this.btnRSAVerify.Location = new System.Drawing.Point(300, 175);
            this.btnRSAVerify.Name = "btnRSAVerify";
            this.btnRSAVerify.Size = new System.Drawing.Size(80, 30);
            this.btnRSAVerify.TabIndex = 1;
            this.btnRSAVerify.Text = "验签";
            this.btnRSAVerify.UseVisualStyleBackColor = true;
            this.btnRSAVerify.Click += new System.EventHandler(this.btnRSAVerify_Click);
            // 
            // textRSASignData
            // 
            this.textRSASignData.Location = new System.Drawing.Point(80, 60);
            this.textRSASignData.Multiline = true;
            this.textRSASignData.Name = "textRSASignData";
            this.textRSASignData.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textRSASignData.Size = new System.Drawing.Size(885, 50);
            this.textRSASignData.TabIndex = 2;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(15, 63);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(59, 17);
            this.label7.TabIndex = 3;
            this.label7.Text = "原文数据:";
            // 
            // textRSASignature
            // 
            this.textRSASignature.Location = new System.Drawing.Point(80, 120);
            this.textRSASignature.Multiline = true;
            this.textRSASignature.Name = "textRSASignature";
            this.textRSASignature.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textRSASignature.Size = new System.Drawing.Size(885, 50);
            this.textRSASignature.TabIndex = 4;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(15, 123);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(35, 17);
            this.label8.TabIndex = 5;
            this.label8.Text = "签名:";
            // 
            // comboRSAType
            // 
            this.comboRSAType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboRSAType.FormattingEnabled = true;
            this.comboRSAType.Items.AddRange(new object[] {
            "RSA",
            "RSA2"});
            this.comboRSAType.Location = new System.Drawing.Point(80, 25);
            this.comboRSAType.Name = "comboRSAType";
            this.comboRSAType.Size = new System.Drawing.Size(100, 25);
            this.comboRSAType.TabIndex = 6;
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(15, 28);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(59, 17);
            this.label9.TabIndex = 7;
            this.label9.Text = "签名类型:";
            // 
            // labelRSAVerifyResult
            // 
            this.labelRSAVerifyResult.AutoSize = true;
            this.labelRSAVerifyResult.Location = new System.Drawing.Point(400, 182);
            this.labelRSAVerifyResult.Name = "labelRSAVerifyResult";
            this.labelRSAVerifyResult.Size = new System.Drawing.Size(59, 17);
            this.labelRSAVerifyResult.TabIndex = 8;
            this.labelRSAVerifyResult.Text = "验签结果:";
            // 
            // tabSM4
            // 
            this.tabSM4.Controls.Add(this.groupBoxSM4Encrypt);
            this.tabSM4.Controls.Add(this.groupBoxSM4Keys);
            this.tabSM4.Location = new System.Drawing.Point(4, 24);
            this.tabSM4.Name = "tabSM4";
            this.tabSM4.Padding = new System.Windows.Forms.Padding(3);
            this.tabSM4.Size = new System.Drawing.Size(992, 622);
            this.tabSM4.TabIndex = 1;
            this.tabSM4.Text = "SM4算法";
            this.tabSM4.UseVisualStyleBackColor = true;
            // 
            // groupBoxSM4Keys
            // 
            this.groupBoxSM4Keys.Controls.Add(this.label11);
            this.groupBoxSM4Keys.Controls.Add(this.textSM4IV);
            this.groupBoxSM4Keys.Controls.Add(this.label10);
            this.groupBoxSM4Keys.Controls.Add(this.textSM4Key);
            this.groupBoxSM4Keys.Controls.Add(this.btnGenerateSM4IV);
            this.groupBoxSM4Keys.Controls.Add(this.btnGenerateSM4Key);
            this.groupBoxSM4Keys.Location = new System.Drawing.Point(6, 6);
            this.groupBoxSM4Keys.Name = "groupBoxSM4Keys";
            this.groupBoxSM4Keys.Size = new System.Drawing.Size(980, 140);
            this.groupBoxSM4Keys.TabIndex = 0;
            this.groupBoxSM4Keys.TabStop = false;
            this.groupBoxSM4Keys.Text = "SM4密钥生成";
            // 
            // btnGenerateSM4Key
            // 
            this.btnGenerateSM4Key.Location = new System.Drawing.Point(800, 35);
            this.btnGenerateSM4Key.Name = "btnGenerateSM4Key";
            this.btnGenerateSM4Key.Size = new System.Drawing.Size(80, 30);
            this.btnGenerateSM4Key.TabIndex = 0;
            this.btnGenerateSM4Key.Text = "生成密钥";
            this.btnGenerateSM4Key.UseVisualStyleBackColor = true;
            this.btnGenerateSM4Key.Click += new System.EventHandler(this.btnGenerateSM4Key_Click);
            // 
            // btnGenerateSM4IV
            // 
            this.btnGenerateSM4IV.Location = new System.Drawing.Point(800, 85);
            this.btnGenerateSM4IV.Name = "btnGenerateSM4IV";
            this.btnGenerateSM4IV.Size = new System.Drawing.Size(80, 30);
            this.btnGenerateSM4IV.TabIndex = 1;
            this.btnGenerateSM4IV.Text = "生成向量";
            this.btnGenerateSM4IV.UseVisualStyleBackColor = true;
            this.btnGenerateSM4IV.Click += new System.EventHandler(this.btnGenerateSM4IV_Click);
            // 
            // textSM4Key
            // 
            this.textSM4Key.Location = new System.Drawing.Point(80, 35);
            this.textSM4Key.Name = "textSM4Key";
            this.textSM4Key.Size = new System.Drawing.Size(700, 23);
            this.textSM4Key.TabIndex = 2;
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Location = new System.Drawing.Point(15, 38);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(59, 17);
            this.label10.TabIndex = 3;
            this.label10.Text = "SM4密钥:";
            // 
            // textSM4IV
            // 
            this.textSM4IV.Location = new System.Drawing.Point(80, 85);
            this.textSM4IV.Name = "textSM4IV";
            this.textSM4IV.Size = new System.Drawing.Size(700, 23);
            this.textSM4IV.TabIndex = 4;
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Location = new System.Drawing.Point(15, 88);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(59, 17);
            this.label11.TabIndex = 5;
            this.label11.Text = "初始向量:";
            // 
            // groupBoxSM4Encrypt
            // 
            this.groupBoxSM4Encrypt.Controls.Add(this.label15);
            this.groupBoxSM4Encrypt.Controls.Add(this.comboSM4Padding);
            this.groupBoxSM4Encrypt.Controls.Add(this.label14);
            this.groupBoxSM4Encrypt.Controls.Add(this.comboSM4Mode);
            this.groupBoxSM4Encrypt.Controls.Add(this.label13);
            this.groupBoxSM4Encrypt.Controls.Add(this.textSM4CipherText);
            this.groupBoxSM4Encrypt.Controls.Add(this.label12);
            this.groupBoxSM4Encrypt.Controls.Add(this.textSM4PlainText);
            this.groupBoxSM4Encrypt.Controls.Add(this.btnSM4Decrypt);
            this.groupBoxSM4Encrypt.Controls.Add(this.btnSM4Encrypt);
            this.groupBoxSM4Encrypt.Location = new System.Drawing.Point(6, 152);
            this.groupBoxSM4Encrypt.Name = "groupBoxSM4Encrypt";
            this.groupBoxSM4Encrypt.Size = new System.Drawing.Size(980, 250);
            this.groupBoxSM4Encrypt.TabIndex = 1;
            this.groupBoxSM4Encrypt.TabStop = false;
            this.groupBoxSM4Encrypt.Text = "SM4加密解密";
            // 
            // btnSM4Encrypt
            // 
            this.btnSM4Encrypt.Location = new System.Drawing.Point(200, 210);
            this.btnSM4Encrypt.Name = "btnSM4Encrypt";
            this.btnSM4Encrypt.Size = new System.Drawing.Size(80, 30);
            this.btnSM4Encrypt.TabIndex = 0;
            this.btnSM4Encrypt.Text = "加密";
            this.btnSM4Encrypt.UseVisualStyleBackColor = true;
            this.btnSM4Encrypt.Click += new System.EventHandler(this.btnSM4Encrypt_Click);
            // 
            // btnSM4Decrypt
            // 
            this.btnSM4Decrypt.Location = new System.Drawing.Point(300, 210);
            this.btnSM4Decrypt.Name = "btnSM4Decrypt";
            this.btnSM4Decrypt.Size = new System.Drawing.Size(80, 30);
            this.btnSM4Decrypt.TabIndex = 1;
            this.btnSM4Decrypt.Text = "解密";
            this.btnSM4Decrypt.UseVisualStyleBackColor = true;
            this.btnSM4Decrypt.Click += new System.EventHandler(this.btnSM4Decrypt_Click);
            // 
            // textSM4PlainText
            // 
            this.textSM4PlainText.Location = new System.Drawing.Point(80, 95);
            this.textSM4PlainText.Multiline = true;
            this.textSM4PlainText.Name = "textSM4PlainText";
            this.textSM4PlainText.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textSM4PlainText.Size = new System.Drawing.Size(885, 50);
            this.textSM4PlainText.TabIndex = 2;
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Location = new System.Drawing.Point(15, 98);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(35, 17);
            this.label12.TabIndex = 3;
            this.label12.Text = "明文:";
            // 
            // textSM4CipherText
            // 
            this.textSM4CipherText.Location = new System.Drawing.Point(80, 155);
            this.textSM4CipherText.Multiline = true;
            this.textSM4CipherText.Name = "textSM4CipherText";
            this.textSM4CipherText.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textSM4CipherText.Size = new System.Drawing.Size(885, 50);
            this.textSM4CipherText.TabIndex = 4;
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Location = new System.Drawing.Point(15, 158);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(35, 17);
            this.label13.TabIndex = 5;
            this.label13.Text = "密文:";
            // 
            // comboSM4Mode
            // 
            this.comboSM4Mode.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboSM4Mode.FormattingEnabled = true;
            this.comboSM4Mode.Items.AddRange(new object[] {
            "ECB",
            "CBC"});
            this.comboSM4Mode.Location = new System.Drawing.Point(80, 25);
            this.comboSM4Mode.Name = "comboSM4Mode";
            this.comboSM4Mode.Size = new System.Drawing.Size(100, 25);
            this.comboSM4Mode.TabIndex = 6;
            this.comboSM4Mode.SelectedIndexChanged += new System.EventHandler(this.comboSM4Mode_SelectedIndexChanged);
            // 
            // label14
            // 
            this.label14.AutoSize = true;
            this.label14.Location = new System.Drawing.Point(15, 28);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(59, 17);
            this.label14.TabIndex = 7;
            this.label14.Text = "加密模式:";
            // 
            // comboSM4Padding
            // 
            this.comboSM4Padding.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboSM4Padding.FormattingEnabled = true;
            this.comboSM4Padding.Items.AddRange(new object[] {
            "PKCS7",
            "PKCS5",
            "NoPadding"});
            this.comboSM4Padding.Location = new System.Drawing.Point(280, 25);
            this.comboSM4Padding.Name = "comboSM4Padding";
            this.comboSM4Padding.Size = new System.Drawing.Size(100, 25);
            this.comboSM4Padding.TabIndex = 8;
            // 
            // label15
            // 
            this.label15.AutoSize = true;
            this.label15.Location = new System.Drawing.Point(215, 28);
            this.label15.Name = "label15";
            this.label15.Size = new System.Drawing.Size(59, 17);
            this.label15.TabIndex = 9;
            this.label15.Text = "填充模式:";
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripStatusLabel1});
            this.statusStrip1.Location = new System.Drawing.Point(0, 628);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(1000, 22);
            this.statusStrip1.TabIndex = 1;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            this.toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            this.toolStripStatusLabel1.Size = new System.Drawing.Size(32, 17);
            this.toolStripStatusLabel1.Text = "就绪";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 17F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1000, 650);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.tabControl1);
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "加密工具 - RSA & SM4";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.tabControl1.ResumeLayout(false);
            this.tabRSA.ResumeLayout(false);
            this.groupBoxRSAKeys.ResumeLayout(false);
            this.groupBoxRSAKeys.PerformLayout();
            this.groupBoxRSAEncrypt.ResumeLayout(false);
            this.groupBoxRSAEncrypt.PerformLayout();
            this.groupBoxRSASign.ResumeLayout(false);
            this.groupBoxRSASign.PerformLayout();
            this.tabSM4.ResumeLayout(false);
            this.groupBoxSM4Keys.ResumeLayout(false);
            this.groupBoxSM4Keys.PerformLayout();
            this.groupBoxSM4Encrypt.ResumeLayout(false);
            this.groupBoxSM4Encrypt.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

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
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.TextBox textSM4IV;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.TextBox textSM4Key;
        private System.Windows.Forms.Button btnGenerateSM4IV;
        private System.Windows.Forms.Button btnGenerateSM4Key;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
    }
}
