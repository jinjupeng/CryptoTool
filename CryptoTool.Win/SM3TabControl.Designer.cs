namespace CryptoTool.Win
{
    partial class SM3TabControl : UserControl
    {
        /// <summary> 
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region 组件设计器生成的代码

        /// <summary> 
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            groupBoxSM3Hash = new GroupBox();
            labelSM3DataFormat = new Label();
            comboSM3DataFormat = new ComboBox();
            labelSM3OutputFormat = new Label();
            comboSM3OutputFormat = new ComboBox();
            label1 = new Label();
            textSM3Input = new TextBox();
            label2 = new Label();
            textSM3Output = new TextBox();
            btnSM3Hash = new Button();
            btnSM3Clear = new Button();
            groupBoxSM3File = new GroupBox();
            labelSM3FileHashFormat = new Label();
            comboSM3FileHashFormat = new ComboBox();
            label3 = new Label();
            textSM3FilePath = new TextBox();
            btnSM3SelectFile = new Button();
            label4 = new Label();
            textSM3FileHash = new TextBox();
            btnSM3ComputeFileHash = new Button();
            groupBoxSM3Verify = new GroupBox();
            labelSM3VerifyDataFormat = new Label();
            comboSM3VerifyDataFormat = new ComboBox();
            labelSM3VerifyHashFormat = new Label();
            comboSM3VerifyHashFormat = new ComboBox();
            label5 = new Label();
            textSM3VerifyData = new TextBox();
            label6 = new Label();
            textSM3VerifyHash = new TextBox();
            btnSM3Verify = new Button();
            labelSM3VerifyResult = new Label();
            groupBoxSM3HMAC = new GroupBox();
            labelSM3HMACDataFormat = new Label();
            comboSM3HMACDataFormat = new ComboBox();
            labelSM3HMACOutputFormat = new Label();
            comboSM3HMACOutputFormat = new ComboBox();
            label7 = new Label();
            textSM3HMACData = new TextBox();
            label8 = new Label();
            textSM3HMACKey = new TextBox();
            label9 = new Label();
            textSM3HMACOutput = new TextBox();
            btnSM3HMAC = new Button();
            groupBoxSM3Hash.SuspendLayout();
            groupBoxSM3File.SuspendLayout();
            groupBoxSM3Verify.SuspendLayout();
            groupBoxSM3HMAC.SuspendLayout();
            SuspendLayout();
            // 
            // groupBoxSM3Hash
            // 
            groupBoxSM3Hash.Controls.Add(labelSM3DataFormat);
            groupBoxSM3Hash.Controls.Add(comboSM3DataFormat);
            groupBoxSM3Hash.Controls.Add(labelSM3OutputFormat);
            groupBoxSM3Hash.Controls.Add(comboSM3OutputFormat);
            groupBoxSM3Hash.Controls.Add(label1);
            groupBoxSM3Hash.Controls.Add(textSM3Input);
            groupBoxSM3Hash.Controls.Add(label2);
            groupBoxSM3Hash.Controls.Add(textSM3Output);
            groupBoxSM3Hash.Controls.Add(btnSM3Hash);
            groupBoxSM3Hash.Controls.Add(btnSM3Clear);
            groupBoxSM3Hash.Location = new Point(8, 7);
            groupBoxSM3Hash.Margin = new Padding(4);
            groupBoxSM3Hash.Name = "groupBoxSM3Hash";
            groupBoxSM3Hash.Padding = new Padding(4);
            groupBoxSM3Hash.Size = new Size(1260, 200);
            groupBoxSM3Hash.TabIndex = 0;
            groupBoxSM3Hash.TabStop = false;
            groupBoxSM3Hash.Text = "SM3哈希计算";
            // 
            // labelSM3DataFormat
            // 
            labelSM3DataFormat.AutoSize = true;
            labelSM3DataFormat.Location = new Point(19, 33);
            labelSM3DataFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM3DataFormat.Name = "labelSM3DataFormat";
            labelSM3DataFormat.Size = new Size(88, 20);
            labelSM3DataFormat.TabIndex = 0;
            labelSM3DataFormat.Text = "输入格式:";
            // 
            // comboSM3DataFormat
            // 
            comboSM3DataFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM3DataFormat.FormattingEnabled = true;
            comboSM3DataFormat.Items.AddRange(new object[] { "Text", "Hex", "Base64" });
            comboSM3DataFormat.Location = new Point(110, 29);
            comboSM3DataFormat.Margin = new Padding(4);
            comboSM3DataFormat.Name = "comboSM3DataFormat";
            comboSM3DataFormat.Size = new Size(127, 28);
            comboSM3DataFormat.TabIndex = 1;
            comboSM3DataFormat.SelectedIndexChanged += ComboSM3DataFormat_TabIndexChanged;
            // 
            // labelSM3OutputFormat
            // 
            labelSM3OutputFormat.AutoSize = true;
            labelSM3OutputFormat.Location = new Point(276, 33);
            labelSM3OutputFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM3OutputFormat.Name = "labelSM3OutputFormat";
            labelSM3OutputFormat.Size = new Size(88, 20);
            labelSM3OutputFormat.TabIndex = 2;
            labelSM3OutputFormat.Text = "输出格式:";
            // 
            // comboSM3OutputFormat
            // 
            comboSM3OutputFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM3OutputFormat.FormattingEnabled = true;
            comboSM3OutputFormat.Items.AddRange(new object[] { "Hex", "Base64" });
            comboSM3OutputFormat.Location = new Point(367, 29);
            comboSM3OutputFormat.Margin = new Padding(4);
            comboSM3OutputFormat.Name = "comboSM3OutputFormat";
            comboSM3OutputFormat.Size = new Size(127, 28);
            comboSM3OutputFormat.TabIndex = 3;
            comboSM3OutputFormat.SelectedIndexChanged += ComboSM3OutputFormat_TabIndexChanged;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(19, 75);
            label1.Margin = new Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new Size(88, 20);
            label1.TabIndex = 4;
            label1.Text = "输入数据:";
            // 
            // textSM3Input
            // 
            textSM3Input.Location = new Point(110, 71);
            textSM3Input.Margin = new Padding(4);
            textSM3Input.Multiline = true;
            textSM3Input.Name = "textSM3Input";
            textSM3Input.ScrollBars = ScrollBars.Both;
            textSM3Input.Size = new Size(1130, 50);
            textSM3Input.TabIndex = 5;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(19, 135);
            label2.Margin = new Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new Size(88, 20);
            label2.TabIndex = 6;
            label2.Text = "哈希结果:";
            // 
            // textSM3Output
            // 
            textSM3Output.Location = new Point(110, 131);
            textSM3Output.Margin = new Padding(4);
            textSM3Output.Multiline = true;
            textSM3Output.Name = "textSM3Output";
            textSM3Output.ReadOnly = true;
            textSM3Output.ScrollBars = ScrollBars.Both;
            textSM3Output.Size = new Size(1130, 50);
            textSM3Output.TabIndex = 7;
            // 
            // btnSM3Hash
            // 
            btnSM3Hash.Location = new Point(534, 29);
            btnSM3Hash.Margin = new Padding(4);
            btnSM3Hash.Name = "btnSM3Hash";
            btnSM3Hash.Size = new Size(103, 30);
            btnSM3Hash.TabIndex = 8;
            btnSM3Hash.Text = "计算哈希";
            btnSM3Hash.UseVisualStyleBackColor = true;
            btnSM3Hash.Click += btnSM3Hash_Click;
            // 
            // btnSM3Clear
            // 
            btnSM3Clear.Location = new Point(669, 29);
            btnSM3Clear.Margin = new Padding(4);
            btnSM3Clear.Name = "btnSM3Clear";
            btnSM3Clear.Size = new Size(103, 30);
            btnSM3Clear.TabIndex = 9;
            btnSM3Clear.Text = "清空";
            btnSM3Clear.UseVisualStyleBackColor = true;
            btnSM3Clear.Click += btnSM3Clear_Click;
            // 
            // groupBoxSM3File
            // 
            groupBoxSM3File.Controls.Add(labelSM3FileHashFormat);
            groupBoxSM3File.Controls.Add(comboSM3FileHashFormat);
            groupBoxSM3File.Controls.Add(label3);
            groupBoxSM3File.Controls.Add(textSM3FilePath);
            groupBoxSM3File.Controls.Add(btnSM3SelectFile);
            groupBoxSM3File.Controls.Add(label4);
            groupBoxSM3File.Controls.Add(textSM3FileHash);
            groupBoxSM3File.Controls.Add(btnSM3ComputeFileHash);
            groupBoxSM3File.Location = new Point(8, 220);
            groupBoxSM3File.Margin = new Padding(4);
            groupBoxSM3File.Name = "groupBoxSM3File";
            groupBoxSM3File.Padding = new Padding(4);
            groupBoxSM3File.Size = new Size(1260, 160);
            groupBoxSM3File.TabIndex = 1;
            groupBoxSM3File.TabStop = false;
            groupBoxSM3File.Text = "文件哈希计算";
            // 
            // labelSM3FileHashFormat
            // 
            labelSM3FileHashFormat.AutoSize = true;
            labelSM3FileHashFormat.Location = new Point(19, 33);
            labelSM3FileHashFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM3FileHashFormat.Name = "labelSM3FileHashFormat";
            labelSM3FileHashFormat.Size = new Size(88, 20);
            labelSM3FileHashFormat.TabIndex = 0;
            labelSM3FileHashFormat.Text = "输出格式:";
            // 
            // comboSM3FileHashFormat
            // 
            comboSM3FileHashFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM3FileHashFormat.FormattingEnabled = true;
            comboSM3FileHashFormat.Items.AddRange(new object[] { "Hex", "Base64" });
            comboSM3FileHashFormat.Location = new Point(110, 29);
            comboSM3FileHashFormat.Margin = new Padding(4);
            comboSM3FileHashFormat.Name = "comboSM3FileHashFormat";
            comboSM3FileHashFormat.Size = new Size(127, 28);
            comboSM3FileHashFormat.TabIndex = 1;
            comboSM3FileHashFormat.SelectedIndexChanged += ComboSM3FileHashFormat_TabIndexChanged;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(19, 75);
            label3.Margin = new Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new Size(73, 20);
            label3.TabIndex = 2;
            label3.Text = "文件路径:";
            // 
            // textSM3FilePath
            // 
            textSM3FilePath.Location = new Point(110, 71);
            textSM3FilePath.Margin = new Padding(4);
            textSM3FilePath.Name = "textSM3FilePath";
            textSM3FilePath.Size = new Size(980, 27);
            textSM3FilePath.TabIndex = 3;
            // 
            // btnSM3SelectFile
            // 
            btnSM3SelectFile.Location = new Point(1110, 69);
            btnSM3SelectFile.Margin = new Padding(4);
            btnSM3SelectFile.Name = "btnSM3SelectFile";
            btnSM3SelectFile.Size = new Size(130, 30);
            btnSM3SelectFile.TabIndex = 4;
            btnSM3SelectFile.Text = "选择文件";
            btnSM3SelectFile.UseVisualStyleBackColor = true;
            btnSM3SelectFile.Click += btnSM3SelectFile_Click;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new Point(19, 115);
            label4.Margin = new Padding(4, 0, 4, 0);
            label4.Name = "label4";
            label4.Size = new Size(88, 20);
            label4.TabIndex = 5;
            label4.Text = "哈希结果:";
            // 
            // textSM3FileHash
            // 
            textSM3FileHash.Location = new Point(110, 111);
            textSM3FileHash.Margin = new Padding(4);
            textSM3FileHash.Name = "textSM3FileHash";
            textSM3FileHash.ReadOnly = true;
            textSM3FileHash.Size = new Size(980, 27);
            textSM3FileHash.TabIndex = 6;
            // 
            // btnSM3ComputeFileHash
            // 
            btnSM3ComputeFileHash.Location = new Point(1110, 109);
            btnSM3ComputeFileHash.Margin = new Padding(4);
            btnSM3ComputeFileHash.Name = "btnSM3ComputeFileHash";
            btnSM3ComputeFileHash.Size = new Size(130, 30);
            btnSM3ComputeFileHash.TabIndex = 7;
            btnSM3ComputeFileHash.Text = "计算哈希";
            btnSM3ComputeFileHash.UseVisualStyleBackColor = true;
            btnSM3ComputeFileHash.Click += btnSM3ComputeFileHash_Click;
            // 
            // groupBoxSM3Verify
            // 
            groupBoxSM3Verify.Controls.Add(labelSM3VerifyDataFormat);
            groupBoxSM3Verify.Controls.Add(comboSM3VerifyDataFormat);
            groupBoxSM3Verify.Controls.Add(labelSM3VerifyHashFormat);
            groupBoxSM3Verify.Controls.Add(comboSM3VerifyHashFormat);
            groupBoxSM3Verify.Controls.Add(label5);
            groupBoxSM3Verify.Controls.Add(textSM3VerifyData);
            groupBoxSM3Verify.Controls.Add(label6);
            groupBoxSM3Verify.Controls.Add(textSM3VerifyHash);
            groupBoxSM3Verify.Controls.Add(btnSM3Verify);
            groupBoxSM3Verify.Controls.Add(labelSM3VerifyResult);
            groupBoxSM3Verify.Location = new Point(8, 395);
            groupBoxSM3Verify.Margin = new Padding(4);
            groupBoxSM3Verify.Name = "groupBoxSM3Verify";
            groupBoxSM3Verify.Padding = new Padding(4);
            groupBoxSM3Verify.Size = new Size(1260, 200);
            groupBoxSM3Verify.TabIndex = 2;
            groupBoxSM3Verify.TabStop = false;
            groupBoxSM3Verify.Text = "哈希值验证";
            // 
            // labelSM3VerifyDataFormat
            // 
            labelSM3VerifyDataFormat.AutoSize = true;
            labelSM3VerifyDataFormat.Location = new Point(19, 33);
            labelSM3VerifyDataFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM3VerifyDataFormat.Name = "labelSM3VerifyDataFormat";
            labelSM3VerifyDataFormat.Size = new Size(103, 20);
            labelSM3VerifyDataFormat.TabIndex = 0;
            labelSM3VerifyDataFormat.Text = "数据格式:";
            // 
            // comboSM3VerifyDataFormat
            // 
            comboSM3VerifyDataFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM3VerifyDataFormat.FormattingEnabled = true;
            comboSM3VerifyDataFormat.Items.AddRange(new object[] { "Text", "Hex", "Base64" });
            comboSM3VerifyDataFormat.Location = new Point(125, 29);
            comboSM3VerifyDataFormat.Margin = new Padding(4);
            comboSM3VerifyDataFormat.Name = "comboSM3VerifyDataFormat";
            comboSM3VerifyDataFormat.Size = new Size(127, 28);
            comboSM3VerifyDataFormat.TabIndex = 1;
            comboSM3VerifyDataFormat.SelectedIndexChanged += ComboSM3VerifyDataFormat_TabIndexChanged;
            // 
            // labelSM3VerifyHashFormat
            // 
            labelSM3VerifyHashFormat.AutoSize = true;
            labelSM3VerifyHashFormat.Location = new Point(291, 33);
            labelSM3VerifyHashFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM3VerifyHashFormat.Name = "labelSM3VerifyHashFormat";
            labelSM3VerifyHashFormat.Size = new Size(103, 20);
            labelSM3VerifyHashFormat.TabIndex = 2;
            labelSM3VerifyHashFormat.Text = "哈希格式:";
            // 
            // comboSM3VerifyHashFormat
            // 
            comboSM3VerifyHashFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM3VerifyHashFormat.FormattingEnabled = true;
            comboSM3VerifyHashFormat.Items.AddRange(new object[] { "Hex", "Base64" });
            comboSM3VerifyHashFormat.Location = new Point(397, 29);
            comboSM3VerifyHashFormat.Margin = new Padding(4);
            comboSM3VerifyHashFormat.Name = "comboSM3VerifyHashFormat";
            comboSM3VerifyHashFormat.Size = new Size(127, 28);
            comboSM3VerifyHashFormat.TabIndex = 3;
            comboSM3VerifyHashFormat.SelectedIndexChanged += ComboSM3VerifyHashFormat_TabIndexChanged;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new Point(19, 75);
            label5.Margin = new Padding(4, 0, 4, 0);
            label5.Name = "label5";
            label5.Size = new Size(88, 20);
            label5.TabIndex = 4;
            label5.Text = "原始数据:";
            // 
            // textSM3VerifyData
            // 
            textSM3VerifyData.Location = new Point(110, 71);
            textSM3VerifyData.Margin = new Padding(4);
            textSM3VerifyData.Multiline = true;
            textSM3VerifyData.Name = "textSM3VerifyData";
            textSM3VerifyData.ScrollBars = ScrollBars.Both;
            textSM3VerifyData.Size = new Size(1130, 50);
            textSM3VerifyData.TabIndex = 5;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new Point(19, 135);
            label6.Margin = new Padding(4, 0, 4, 0);
            label6.Name = "label6";
            label6.Size = new Size(73, 20);
            label6.TabIndex = 6;
            label6.Text = "期望哈希:";
            // 
            // textSM3VerifyHash
            // 
            textSM3VerifyHash.Location = new Point(110, 131);
            textSM3VerifyHash.Margin = new Padding(4);
            textSM3VerifyHash.Name = "textSM3VerifyHash";
            textSM3VerifyHash.Size = new Size(880, 27);
            textSM3VerifyHash.TabIndex = 7;
            // 
            // btnSM3Verify
            // 
            btnSM3Verify.Location = new Point(564, 29);
            btnSM3Verify.Margin = new Padding(4);
            btnSM3Verify.Name = "btnSM3Verify";
            btnSM3Verify.Size = new Size(103, 30);
            btnSM3Verify.TabIndex = 8;
            btnSM3Verify.Text = "验证";
            btnSM3Verify.UseVisualStyleBackColor = true;
            btnSM3Verify.Click += btnSM3Verify_Click;
            // 
            // labelSM3VerifyResult
            // 
            labelSM3VerifyResult.AutoSize = true;
            labelSM3VerifyResult.Location = new Point(1010, 135);
            labelSM3VerifyResult.Margin = new Padding(4, 0, 4, 0);
            labelSM3VerifyResult.Name = "labelSM3VerifyResult";
            labelSM3VerifyResult.Size = new Size(88, 20);
            labelSM3VerifyResult.TabIndex = 9;
            labelSM3VerifyResult.Text = "验证结果:";
            // 
            // groupBoxSM3HMAC
            // 
            groupBoxSM3HMAC.Controls.Add(labelSM3HMACDataFormat);
            groupBoxSM3HMAC.Controls.Add(comboSM3HMACDataFormat);
            groupBoxSM3HMAC.Controls.Add(labelSM3HMACOutputFormat);
            groupBoxSM3HMAC.Controls.Add(comboSM3HMACOutputFormat);
            groupBoxSM3HMAC.Controls.Add(label7);
            groupBoxSM3HMAC.Controls.Add(textSM3HMACData);
            groupBoxSM3HMAC.Controls.Add(label8);
            groupBoxSM3HMAC.Controls.Add(textSM3HMACKey);
            groupBoxSM3HMAC.Controls.Add(label9);
            groupBoxSM3HMAC.Controls.Add(textSM3HMACOutput);
            groupBoxSM3HMAC.Controls.Add(btnSM3HMAC);
            groupBoxSM3HMAC.Location = new Point(8, 615);
            groupBoxSM3HMAC.Margin = new Padding(4);
            groupBoxSM3HMAC.Name = "groupBoxSM3HMAC";
            groupBoxSM3HMAC.Padding = new Padding(4);
            groupBoxSM3HMAC.Size = new Size(1260, 220);
            groupBoxSM3HMAC.TabIndex = 3;
            groupBoxSM3HMAC.TabStop = false;
            groupBoxSM3HMAC.Text = "HMAC-SM3计算";
            // 
            // labelSM3HMACDataFormat
            // 
            labelSM3HMACDataFormat.AutoSize = true;
            labelSM3HMACDataFormat.Location = new Point(19, 33);
            labelSM3HMACDataFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM3HMACDataFormat.Name = "labelSM3HMACDataFormat";
            labelSM3HMACDataFormat.Size = new Size(88, 20);
            labelSM3HMACDataFormat.TabIndex = 0;
            labelSM3HMACDataFormat.Text = "数据格式:";
            // 
            // comboSM3HMACDataFormat
            // 
            comboSM3HMACDataFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM3HMACDataFormat.FormattingEnabled = true;
            comboSM3HMACDataFormat.Items.AddRange(new object[] { "Text", "Hex", "Base64" });
            comboSM3HMACDataFormat.Location = new Point(110, 29);
            comboSM3HMACDataFormat.Margin = new Padding(4);
            comboSM3HMACDataFormat.Name = "comboSM3HMACDataFormat";
            comboSM3HMACDataFormat.Size = new Size(127, 28);
            comboSM3HMACDataFormat.TabIndex = 1;
            comboSM3HMACDataFormat.SelectedIndexChanged += ComboSM3HMACDataFormat_TabIndexChanged;
            // 
            // labelSM3HMACOutputFormat
            // 
            labelSM3HMACOutputFormat.AutoSize = true;
            labelSM3HMACOutputFormat.Location = new Point(276, 33);
            labelSM3HMACOutputFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM3HMACOutputFormat.Name = "labelSM3HMACOutputFormat";
            labelSM3HMACOutputFormat.Size = new Size(88, 20);
            labelSM3HMACOutputFormat.TabIndex = 2;
            labelSM3HMACOutputFormat.Text = "输出格式:";
            // 
            // comboSM3HMACOutputFormat
            // 
            comboSM3HMACOutputFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM3HMACOutputFormat.FormattingEnabled = true;
            comboSM3HMACOutputFormat.Items.AddRange(new object[] { "Hex", "Base64" });
            comboSM3HMACOutputFormat.Location = new Point(367, 29);
            comboSM3HMACOutputFormat.Margin = new Padding(4);
            comboSM3HMACOutputFormat.Name = "comboSM3HMACOutputFormat";
            comboSM3HMACOutputFormat.Size = new Size(127, 28);
            comboSM3HMACOutputFormat.TabIndex = 3;
            comboSM3HMACOutputFormat.SelectedIndexChanged += ComboSM3HMACOutputFormat_TabIndexChanged;
            // 
            // label7
            // 
            label7.AutoSize = true;
            label7.Location = new Point(19, 75);
            label7.Margin = new Padding(4, 0, 4, 0);
            label7.Name = "label7";
            label7.Size = new Size(88, 20);
            label7.TabIndex = 4;
            label7.Text = "输入数据:";
            // 
            // textSM3HMACData
            // 
            textSM3HMACData.Location = new Point(110, 71);
            textSM3HMACData.Margin = new Padding(4);
            textSM3HMACData.Multiline = true;
            textSM3HMACData.Name = "textSM3HMACData";
            textSM3HMACData.ScrollBars = ScrollBars.Both;
            textSM3HMACData.Size = new Size(1130, 45);
            textSM3HMACData.TabIndex = 5;
            // 
            // label8
            // 
            label8.AutoSize = true;
            label8.Location = new Point(19, 130);
            label8.Margin = new Padding(4, 0, 4, 0);
            label8.Name = "label8";
            label8.Size = new Size(88, 20);
            label8.TabIndex = 6;
            label8.Text = "HMAC密钥:";
            // 
            // textSM3HMACKey
            // 
            textSM3HMACKey.Location = new Point(110, 126);
            textSM3HMACKey.Margin = new Padding(4);
            textSM3HMACKey.Name = "textSM3HMACKey";
            textSM3HMACKey.Size = new Size(1130, 27);
            textSM3HMACKey.TabIndex = 7;
            // 
            // label9
            // 
            label9.AutoSize = true;
            label9.Location = new Point(19, 170);
            label9.Margin = new Padding(4, 0, 4, 0);
            label9.Name = "label9";
            label9.Size = new Size(103, 20);
            label9.TabIndex = 8;
            label9.Text = "HMAC结果:";
            // 
            // textSM3HMACOutput
            // 
            textSM3HMACOutput.Location = new Point(125, 166);
            textSM3HMACOutput.Margin = new Padding(4);
            textSM3HMACOutput.Name = "textSM3HMACOutput";
            textSM3HMACOutput.ReadOnly = true;
            textSM3HMACOutput.Size = new Size(1115, 27);
            textSM3HMACOutput.TabIndex = 9;
            // 
            // btnSM3HMAC
            // 
            btnSM3HMAC.Location = new Point(534, 29);
            btnSM3HMAC.Margin = new Padding(4);
            btnSM3HMAC.Name = "btnSM3HMAC";
            btnSM3HMAC.Size = new Size(130, 30);
            btnSM3HMAC.TabIndex = 10;
            btnSM3HMAC.Text = "计算HMAC";
            btnSM3HMAC.UseVisualStyleBackColor = true;
            btnSM3HMAC.Click += btnSM3HMAC_Click;
            // 
            // SM3TabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(groupBoxSM3Hash);
            Controls.Add(groupBoxSM3File);
            Controls.Add(groupBoxSM3Verify);
            Controls.Add(groupBoxSM3HMAC);
            Margin = new Padding(4);
            Name = "SM3TabControl";
            Size = new Size(1278, 850);
            groupBoxSM3Hash.ResumeLayout(false);
            groupBoxSM3Hash.PerformLayout();
            groupBoxSM3File.ResumeLayout(false);
            groupBoxSM3File.PerformLayout();
            groupBoxSM3Verify.ResumeLayout(false);
            groupBoxSM3Verify.PerformLayout();
            groupBoxSM3HMAC.ResumeLayout(false);
            groupBoxSM3HMAC.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private GroupBox groupBoxSM3Hash;
        private Label labelSM3DataFormat;
        private ComboBox comboSM3DataFormat;
        private Label labelSM3OutputFormat;
        private ComboBox comboSM3OutputFormat;
        private Label label1;
        private TextBox textSM3Input;
        private Label label2;
        private TextBox textSM3Output;
        private Button btnSM3Hash;
        private Button btnSM3Clear;
        private GroupBox groupBoxSM3File;
        private Label labelSM3FileHashFormat;
        private ComboBox comboSM3FileHashFormat;
        private Label label3;
        private TextBox textSM3FilePath;
        private Button btnSM3SelectFile;
        private Label label4;
        private TextBox textSM3FileHash;
        private Button btnSM3ComputeFileHash;
        private GroupBox groupBoxSM3Verify;
        private Label labelSM3VerifyDataFormat;
        private ComboBox comboSM3VerifyDataFormat;
        private Label labelSM3VerifyHashFormat;
        private ComboBox comboSM3VerifyHashFormat;
        private Label label5;
        private TextBox textSM3VerifyData;
        private Label label6;
        private TextBox textSM3VerifyHash;
        private Button btnSM3Verify;
        private Label labelSM3VerifyResult;
        private GroupBox groupBoxSM3HMAC;
        private Label labelSM3HMACDataFormat;
        private ComboBox comboSM3HMACDataFormat;
        private Label labelSM3HMACOutputFormat;
        private ComboBox comboSM3HMACOutputFormat;
        private Label label7;
        private TextBox textSM3HMACData;
        private Label label8;
        private TextBox textSM3HMACKey;
        private Label label9;
        private TextBox textSM3HMACOutput;
        private Button btnSM3HMAC;
    }
}