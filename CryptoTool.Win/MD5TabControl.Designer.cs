namespace CryptoTool.Win
{
    partial class MD5TabControl : UserControl
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
            mainTableLayout = new TableLayoutPanel();
            groupBoxMD5Hash = new GroupBox();
            tableLayoutMD5Hash = new TableLayoutPanel();
            panelMD5HashControls = new Panel();
            labelMD5DataFormat = new Label();
            comboMD5DataFormat = new ComboBox();
            labelMD5OutputFormat = new Label();
            comboMD5OutputFormat = new ComboBox();
            btnMD5Hash = new Button();
            btnMD5Clear = new Button();
            label1 = new Label();
            textMD5Input = new TextBox();
            label2 = new Label();
            textMD5Output = new TextBox();
            groupBoxMD5File = new GroupBox();
            tableLayoutMD5File = new TableLayoutPanel();
            panelMD5FileControls = new Panel();
            labelMD5FileHashFormat = new Label();
            comboMD5FileHashFormat = new ComboBox();
            label3 = new Label();
            panelMD5FilePath = new Panel();
            textMD5FilePath = new TextBox();
            btnMD5SelectFile = new Button();
            label4 = new Label();
            panelMD5FileHash = new Panel();
            textMD5FileHash = new TextBox();
            btnMD5ComputeFileHash = new Button();
            groupBoxMD5Verify = new GroupBox();
            tableLayoutMD5Verify = new TableLayoutPanel();
            panelMD5VerifyControls = new Panel();
            labelMD5VerifyDataFormat = new Label();
            comboMD5VerifyDataFormat = new ComboBox();
            labelMD5VerifyHashFormat = new Label();
            comboMD5VerifyHashFormat = new ComboBox();
            btnMD5Verify = new Button();
            label5 = new Label();
            textMD5VerifyData = new TextBox();
            label6 = new Label();
            panelMD5VerifyHashResult = new Panel();
            textMD5VerifyHash = new TextBox();
            labelMD5VerifyResult = new Label();
            mainTableLayout.SuspendLayout();
            groupBoxMD5Hash.SuspendLayout();
            tableLayoutMD5Hash.SuspendLayout();
            panelMD5HashControls.SuspendLayout();
            groupBoxMD5File.SuspendLayout();
            tableLayoutMD5File.SuspendLayout();
            panelMD5FileControls.SuspendLayout();
            panelMD5FilePath.SuspendLayout();
            panelMD5FileHash.SuspendLayout();
            groupBoxMD5Verify.SuspendLayout();
            tableLayoutMD5Verify.SuspendLayout();
            panelMD5VerifyControls.SuspendLayout();
            panelMD5VerifyHashResult.SuspendLayout();
            SuspendLayout();
            // 
            // mainTableLayout
            // 
            mainTableLayout.ColumnCount = 1;
            mainTableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            mainTableLayout.Controls.Add(groupBoxMD5Hash, 0, 0);
            mainTableLayout.Controls.Add(groupBoxMD5File, 0, 1);
            mainTableLayout.Controls.Add(groupBoxMD5Verify, 0, 2);
            mainTableLayout.Dock = DockStyle.Fill;
            mainTableLayout.Location = new Point(0, 0);
            mainTableLayout.Margin = new Padding(4);
            mainTableLayout.Name = "mainTableLayout";
            mainTableLayout.Padding = new Padding(8);
            mainTableLayout.RowCount = 3;
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 40F));
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 30F));
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 30F));
            mainTableLayout.Size = new Size(1278, 850);
            mainTableLayout.TabIndex = 0;
            // 
            // groupBoxMD5Hash
            // 
            groupBoxMD5Hash.Controls.Add(tableLayoutMD5Hash);
            groupBoxMD5Hash.Dock = DockStyle.Fill;
            groupBoxMD5Hash.Location = new Point(12, 12);
            groupBoxMD5Hash.Margin = new Padding(4);
            groupBoxMD5Hash.Name = "groupBoxMD5Hash";
            groupBoxMD5Hash.Padding = new Padding(8);
            groupBoxMD5Hash.Size = new Size(1254, 325);
            groupBoxMD5Hash.TabIndex = 0;
            groupBoxMD5Hash.TabStop = false;
            groupBoxMD5Hash.Text = "MD5哈希计算";
            // 
            // tableLayoutMD5Hash
            // 
            tableLayoutMD5Hash.ColumnCount = 1;
            tableLayoutMD5Hash.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutMD5Hash.Controls.Add(panelMD5HashControls, 0, 0);
            tableLayoutMD5Hash.Controls.Add(label1, 0, 1);
            tableLayoutMD5Hash.Controls.Add(textMD5Input, 0, 2);
            tableLayoutMD5Hash.Controls.Add(label2, 0, 3);
            tableLayoutMD5Hash.Controls.Add(textMD5Output, 0, 4);
            tableLayoutMD5Hash.Dock = DockStyle.Fill;
            tableLayoutMD5Hash.Location = new Point(8, 28);
            tableLayoutMD5Hash.Name = "tableLayoutMD5Hash";
            tableLayoutMD5Hash.RowCount = 5;
            tableLayoutMD5Hash.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));
            tableLayoutMD5Hash.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutMD5Hash.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutMD5Hash.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutMD5Hash.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutMD5Hash.Size = new Size(1238, 289);
            tableLayoutMD5Hash.TabIndex = 0;
            // 
            // panelMD5HashControls
            // 
            panelMD5HashControls.Controls.Add(btnMD5Clear);
            panelMD5HashControls.Controls.Add(btnMD5Hash);
            panelMD5HashControls.Controls.Add(comboMD5OutputFormat);
            panelMD5HashControls.Controls.Add(labelMD5OutputFormat);
            panelMD5HashControls.Controls.Add(comboMD5DataFormat);
            panelMD5HashControls.Controls.Add(labelMD5DataFormat);
            panelMD5HashControls.Dock = DockStyle.Fill;
            panelMD5HashControls.Location = new Point(3, 3);
            panelMD5HashControls.Name = "panelMD5HashControls";
            panelMD5HashControls.Size = new Size(1232, 34);
            panelMD5HashControls.TabIndex = 0;
            // 
            // labelMD5DataFormat
            // 
            labelMD5DataFormat.AutoSize = true;
            labelMD5DataFormat.Location = new Point(0, 8);
            labelMD5DataFormat.Margin = new Padding(4, 0, 4, 0);
            labelMD5DataFormat.Name = "labelMD5DataFormat";
            labelMD5DataFormat.Size = new Size(88, 20);
            labelMD5DataFormat.TabIndex = 0;
            labelMD5DataFormat.Text = "输入格式:";
            // 
            // comboMD5DataFormat
            // 
            comboMD5DataFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboMD5DataFormat.FormattingEnabled = true;
            comboMD5DataFormat.Items.AddRange(new object[] { "Text", "Hex", "Base64" });
            comboMD5DataFormat.Location = new Point(95, 4);
            comboMD5DataFormat.Margin = new Padding(4);
            comboMD5DataFormat.Name = "comboMD5DataFormat";
            comboMD5DataFormat.Size = new Size(127, 28);
            comboMD5DataFormat.TabIndex = 1;
            // 
            // labelMD5OutputFormat
            // 
            labelMD5OutputFormat.AutoSize = true;
            labelMD5OutputFormat.Location = new Point(240, 8);
            labelMD5OutputFormat.Margin = new Padding(4, 0, 4, 0);
            labelMD5OutputFormat.Name = "labelMD5OutputFormat";
            labelMD5OutputFormat.Size = new Size(88, 20);
            labelMD5OutputFormat.TabIndex = 2;
            labelMD5OutputFormat.Text = "输出格式:";
            // 
            // comboMD5OutputFormat
            // 
            comboMD5OutputFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboMD5OutputFormat.FormattingEnabled = true;
            comboMD5OutputFormat.Items.AddRange(new object[] { "Hex", "Base64" });
            comboMD5OutputFormat.Location = new Point(335, 4);
            comboMD5OutputFormat.Margin = new Padding(4);
            comboMD5OutputFormat.Name = "comboMD5OutputFormat";
            comboMD5OutputFormat.Size = new Size(127, 28);
            comboMD5OutputFormat.TabIndex = 3;
            // 
            // btnMD5Hash
            // 
            btnMD5Hash.Location = new Point(480, 2);
            btnMD5Hash.Margin = new Padding(4);
            btnMD5Hash.Name = "btnMD5Hash";
            btnMD5Hash.Size = new Size(103, 30);
            btnMD5Hash.TabIndex = 8;
            btnMD5Hash.Text = "计算哈希";
            btnMD5Hash.UseVisualStyleBackColor = true;
            btnMD5Hash.Click += btnMD5Hash_Click;
            // 
            // btnMD5Clear
            // 
            btnMD5Clear.Location = new Point(600, 2);
            btnMD5Clear.Margin = new Padding(4);
            btnMD5Clear.Name = "btnMD5Clear";
            btnMD5Clear.Size = new Size(103, 30);
            btnMD5Clear.TabIndex = 9;
            btnMD5Clear.Text = "清空";
            btnMD5Clear.UseVisualStyleBackColor = true;
            btnMD5Clear.Click += btnMD5Clear_Click;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Dock = DockStyle.Bottom;
            label1.Location = new Point(4, 45);
            label1.Margin = new Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new Size(1230, 20);
            label1.TabIndex = 4;
            label1.Text = "输入数据:";
            // 
            // textMD5Input
            // 
            textMD5Input.Dock = DockStyle.Fill;
            textMD5Input.Location = new Point(4, 69);
            textMD5Input.Margin = new Padding(4);
            textMD5Input.Multiline = true;
            textMD5Input.Name = "textMD5Input";
            textMD5Input.ScrollBars = ScrollBars.Both;
            textMD5Input.Size = new Size(1230, 91);
            textMD5Input.TabIndex = 5;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Dock = DockStyle.Bottom;
            label2.Location = new Point(4, 185);
            label2.Margin = new Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new Size(1230, 20);
            label2.TabIndex = 6;
            label2.Text = "哈希结果:";
            // 
            // textMD5Output
            // 
            textMD5Output.Dock = DockStyle.Fill;
            textMD5Output.Location = new Point(4, 209);
            textMD5Output.Margin = new Padding(4);
            textMD5Output.Multiline = true;
            textMD5Output.Name = "textMD5Output";
            textMD5Output.ReadOnly = true;
            textMD5Output.ScrollBars = ScrollBars.Both;
            textMD5Output.Size = new Size(1230, 76);
            textMD5Output.TabIndex = 7;
            // 
            // groupBoxMD5File
            // 
            groupBoxMD5File.Controls.Add(tableLayoutMD5File);
            groupBoxMD5File.Dock = DockStyle.Fill;
            groupBoxMD5File.Location = new Point(12, 345);
            groupBoxMD5File.Margin = new Padding(4);
            groupBoxMD5File.Name = "groupBoxMD5File";
            groupBoxMD5File.Padding = new Padding(8);
            groupBoxMD5File.Size = new Size(1254, 242);
            groupBoxMD5File.TabIndex = 1;
            groupBoxMD5File.TabStop = false;
            groupBoxMD5File.Text = "文件哈希计算";
            // 
            // tableLayoutMD5File
            // 
            tableLayoutMD5File.ColumnCount = 1;
            tableLayoutMD5File.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutMD5File.Controls.Add(panelMD5FileControls, 0, 0);
            tableLayoutMD5File.Controls.Add(label3, 0, 1);
            tableLayoutMD5File.Controls.Add(panelMD5FilePath, 0, 2);
            tableLayoutMD5File.Controls.Add(label4, 0, 3);
            tableLayoutMD5File.Controls.Add(panelMD5FileHash, 0, 4);
            tableLayoutMD5File.Dock = DockStyle.Fill;
            tableLayoutMD5File.Location = new Point(8, 28);
            tableLayoutMD5File.Name = "tableLayoutMD5File";
            tableLayoutMD5File.RowCount = 5;
            tableLayoutMD5File.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));
            tableLayoutMD5File.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutMD5File.RowStyles.Add(new RowStyle(SizeType.Absolute, 35F));
            tableLayoutMD5File.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutMD5File.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            tableLayoutMD5File.Size = new Size(1238, 206);
            tableLayoutMD5File.TabIndex = 0;
            // 
            // panelMD5FileControls
            // 
            panelMD5FileControls.Controls.Add(comboMD5FileHashFormat);
            panelMD5FileControls.Controls.Add(labelMD5FileHashFormat);
            panelMD5FileControls.Dock = DockStyle.Fill;
            panelMD5FileControls.Location = new Point(3, 3);
            panelMD5FileControls.Name = "panelMD5FileControls";
            panelMD5FileControls.Size = new Size(1232, 34);
            panelMD5FileControls.TabIndex = 0;
            // 
            // labelMD5FileHashFormat
            // 
            labelMD5FileHashFormat.AutoSize = true;
            labelMD5FileHashFormat.Location = new Point(0, 8);
            labelMD5FileHashFormat.Margin = new Padding(4, 0, 4, 0);
            labelMD5FileHashFormat.Name = "labelMD5FileHashFormat";
            labelMD5FileHashFormat.Size = new Size(88, 20);
            labelMD5FileHashFormat.TabIndex = 0;
            labelMD5FileHashFormat.Text = "输出格式:";
            // 
            // comboMD5FileHashFormat
            // 
            comboMD5FileHashFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboMD5FileHashFormat.FormattingEnabled = true;
            comboMD5FileHashFormat.Items.AddRange(new object[] { "Hex", "Base64" });
            comboMD5FileHashFormat.Location = new Point(95, 4);
            comboMD5FileHashFormat.Margin = new Padding(4);
            comboMD5FileHashFormat.Name = "comboMD5FileHashFormat";
            comboMD5FileHashFormat.Size = new Size(127, 28);
            comboMD5FileHashFormat.TabIndex = 1;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Dock = DockStyle.Bottom;
            label3.Location = new Point(4, 45);
            label3.Margin = new Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new Size(1230, 20);
            label3.TabIndex = 2;
            label3.Text = "文件路径:";
            // 
            // panelMD5FilePath
            // 
            panelMD5FilePath.Controls.Add(btnMD5SelectFile);
            panelMD5FilePath.Controls.Add(textMD5FilePath);
            panelMD5FilePath.Dock = DockStyle.Fill;
            panelMD5FilePath.Location = new Point(3, 68);
            panelMD5FilePath.Name = "panelMD5FilePath";
            panelMD5FilePath.Size = new Size(1232, 29);
            panelMD5FilePath.TabIndex = 3;
            // 
            // textMD5FilePath
            // 
            textMD5FilePath.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMD5FilePath.Location = new Point(0, 1);
            textMD5FilePath.Margin = new Padding(4);
            textMD5FilePath.Name = "textMD5FilePath";
            textMD5FilePath.Size = new Size(1095, 27);
            textMD5FilePath.TabIndex = 3;
            // 
            // btnMD5SelectFile
            // 
            btnMD5SelectFile.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnMD5SelectFile.Location = new Point(1102, 0);
            btnMD5SelectFile.Margin = new Padding(4);
            btnMD5SelectFile.Name = "btnMD5SelectFile";
            btnMD5SelectFile.Size = new Size(130, 30);
            btnMD5SelectFile.TabIndex = 4;
            btnMD5SelectFile.Text = "选择文件";
            btnMD5SelectFile.UseVisualStyleBackColor = true;
            btnMD5SelectFile.Click += btnMD5SelectFile_Click;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Dock = DockStyle.Bottom;
            label4.Location = new Point(4, 105);
            label4.Margin = new Padding(4, 0, 4, 0);
            label4.Name = "label4";
            label4.Size = new Size(1230, 20);
            label4.TabIndex = 5;
            label4.Text = "哈希结果:";
            // 
            // panelMD5FileHash
            // 
            panelMD5FileHash.Controls.Add(btnMD5ComputeFileHash);
            panelMD5FileHash.Controls.Add(textMD5FileHash);
            panelMD5FileHash.Dock = DockStyle.Fill;
            panelMD5FileHash.Location = new Point(3, 128);
            panelMD5FileHash.Name = "panelMD5FileHash";
            panelMD5FileHash.Size = new Size(1232, 75);
            panelMD5FileHash.TabIndex = 6;
            // 
            // textMD5FileHash
            // 
            textMD5FileHash.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMD5FileHash.Location = new Point(0, 1);
            textMD5FileHash.Margin = new Padding(4);
            textMD5FileHash.Multiline = true;
            textMD5FileHash.Name = "textMD5FileHash";
            textMD5FileHash.ReadOnly = true;
            textMD5FileHash.ScrollBars = ScrollBars.Both;
            textMD5FileHash.Size = new Size(1095, 70);
            textMD5FileHash.TabIndex = 6;
            // 
            // btnMD5ComputeFileHash
            // 
            btnMD5ComputeFileHash.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnMD5ComputeFileHash.Location = new Point(1102, 0);
            btnMD5ComputeFileHash.Margin = new Padding(4);
            btnMD5ComputeFileHash.Name = "btnMD5ComputeFileHash";
            btnMD5ComputeFileHash.Size = new Size(130, 30);
            btnMD5ComputeFileHash.TabIndex = 7;
            btnMD5ComputeFileHash.Text = "计算哈希";
            btnMD5ComputeFileHash.UseVisualStyleBackColor = true;
            btnMD5ComputeFileHash.Click += btnMD5ComputeFileHash_Click;
            // 
            // groupBoxMD5Verify
            // 
            groupBoxMD5Verify.Controls.Add(tableLayoutMD5Verify);
            groupBoxMD5Verify.Dock = DockStyle.Fill;
            groupBoxMD5Verify.Location = new Point(12, 595);
            groupBoxMD5Verify.Margin = new Padding(4);
            groupBoxMD5Verify.Name = "groupBoxMD5Verify";
            groupBoxMD5Verify.Padding = new Padding(8);
            groupBoxMD5Verify.Size = new Size(1254, 243);
            groupBoxMD5Verify.TabIndex = 2;
            groupBoxMD5Verify.TabStop = false;
            groupBoxMD5Verify.Text = "哈希值验证";
            // 
            // tableLayoutMD5Verify
            // 
            tableLayoutMD5Verify.ColumnCount = 1;
            tableLayoutMD5Verify.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutMD5Verify.Controls.Add(panelMD5VerifyControls, 0, 0);
            tableLayoutMD5Verify.Controls.Add(label5, 0, 1);
            tableLayoutMD5Verify.Controls.Add(textMD5VerifyData, 0, 2);
            tableLayoutMD5Verify.Controls.Add(label6, 0, 3);
            tableLayoutMD5Verify.Controls.Add(panelMD5VerifyHashResult, 0, 4);
            tableLayoutMD5Verify.Dock = DockStyle.Fill;
            tableLayoutMD5Verify.Location = new Point(8, 28);
            tableLayoutMD5Verify.Name = "tableLayoutMD5Verify";
            tableLayoutMD5Verify.RowCount = 5;
            tableLayoutMD5Verify.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));
            tableLayoutMD5Verify.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutMD5Verify.RowStyles.Add(new RowStyle(SizeType.Percent, 60F));
            tableLayoutMD5Verify.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutMD5Verify.RowStyles.Add(new RowStyle(SizeType.Percent, 40F));
            tableLayoutMD5Verify.Size = new Size(1238, 207);
            tableLayoutMD5Verify.TabIndex = 0;
            // 
            // panelMD5VerifyControls
            // 
            panelMD5VerifyControls.Controls.Add(btnMD5Verify);
            panelMD5VerifyControls.Controls.Add(comboMD5VerifyHashFormat);
            panelMD5VerifyControls.Controls.Add(labelMD5VerifyHashFormat);
            panelMD5VerifyControls.Controls.Add(comboMD5VerifyDataFormat);
            panelMD5VerifyControls.Controls.Add(labelMD5VerifyDataFormat);
            panelMD5VerifyControls.Dock = DockStyle.Fill;
            panelMD5VerifyControls.Location = new Point(3, 3);
            panelMD5VerifyControls.Name = "panelMD5VerifyControls";
            panelMD5VerifyControls.Size = new Size(1232, 34);
            panelMD5VerifyControls.TabIndex = 0;
            // 
            // labelMD5VerifyDataFormat
            // 
            labelMD5VerifyDataFormat.AutoSize = true;
            labelMD5VerifyDataFormat.Location = new Point(0, 8);
            labelMD5VerifyDataFormat.Margin = new Padding(4, 0, 4, 0);
            labelMD5VerifyDataFormat.Name = "labelMD5VerifyDataFormat";
            labelMD5VerifyDataFormat.Size = new Size(103, 20);
            labelMD5VerifyDataFormat.TabIndex = 0;
            labelMD5VerifyDataFormat.Text = "数据格式:";
            // 
            // comboMD5VerifyDataFormat
            // 
            comboMD5VerifyDataFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboMD5VerifyDataFormat.FormattingEnabled = true;
            comboMD5VerifyDataFormat.Items.AddRange(new object[] { "Text", "Hex", "Base64" });
            comboMD5VerifyDataFormat.Location = new Point(110, 4);
            comboMD5VerifyDataFormat.Margin = new Padding(4);
            comboMD5VerifyDataFormat.Name = "comboMD5VerifyDataFormat";
            comboMD5VerifyDataFormat.Size = new Size(127, 28);
            comboMD5VerifyDataFormat.TabIndex = 1;
            // 
            // labelMD5VerifyHashFormat
            // 
            labelMD5VerifyHashFormat.AutoSize = true;
            labelMD5VerifyHashFormat.Location = new Point(255, 8);
            labelMD5VerifyHashFormat.Margin = new Padding(4, 0, 4, 0);
            labelMD5VerifyHashFormat.Name = "labelMD5VerifyHashFormat";
            labelMD5VerifyHashFormat.Size = new Size(103, 20);
            labelMD5VerifyHashFormat.TabIndex = 2;
            labelMD5VerifyHashFormat.Text = "哈希格式:";
            // 
            // comboMD5VerifyHashFormat
            // 
            comboMD5VerifyHashFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboMD5VerifyHashFormat.FormattingEnabled = true;
            comboMD5VerifyHashFormat.Items.AddRange(new object[] { "Hex", "Base64" });
            comboMD5VerifyHashFormat.Location = new Point(365, 4);
            comboMD5VerifyHashFormat.Margin = new Padding(4);
            comboMD5VerifyHashFormat.Name = "comboMD5VerifyHashFormat";
            comboMD5VerifyHashFormat.Size = new Size(127, 28);
            comboMD5VerifyHashFormat.TabIndex = 3;
            // 
            // btnMD5Verify
            // 
            btnMD5Verify.Location = new Point(510, 2);
            btnMD5Verify.Margin = new Padding(4);
            btnMD5Verify.Name = "btnMD5Verify";
            btnMD5Verify.Size = new Size(103, 30);
            btnMD5Verify.TabIndex = 8;
            btnMD5Verify.Text = "验证";
            btnMD5Verify.UseVisualStyleBackColor = true;
            btnMD5Verify.Click += btnMD5Verify_Click;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Dock = DockStyle.Bottom;
            label5.Location = new Point(4, 45);
            label5.Margin = new Padding(4, 0, 4, 0);
            label5.Name = "label5";
            label5.Size = new Size(1230, 20);
            label5.TabIndex = 4;
            label5.Text = "原始数据:";
            // 
            // textMD5VerifyData
            // 
            textMD5VerifyData.Dock = DockStyle.Fill;
            textMD5VerifyData.Location = new Point(4, 69);
            textMD5VerifyData.Margin = new Padding(4);
            textMD5VerifyData.Multiline = true;
            textMD5VerifyData.Name = "textMD5VerifyData";
            textMD5VerifyData.ScrollBars = ScrollBars.Both;
            textMD5VerifyData.Size = new Size(1230, 64);
            textMD5VerifyData.TabIndex = 5;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Dock = DockStyle.Bottom;
            label6.Location = new Point(4, 158);
            label6.Margin = new Padding(4, 0, 4, 0);
            label6.Name = "label6";
            label6.Size = new Size(1230, 20);
            label6.TabIndex = 6;
            label6.Text = "期望哈希:";
            // 
            // panelMD5VerifyHashResult
            // 
            panelMD5VerifyHashResult.Controls.Add(labelMD5VerifyResult);
            panelMD5VerifyHashResult.Controls.Add(textMD5VerifyHash);
            panelMD5VerifyHashResult.Dock = DockStyle.Fill;
            panelMD5VerifyHashResult.Location = new Point(3, 181);
            panelMD5VerifyHashResult.Name = "panelMD5VerifyHashResult";
            panelMD5VerifyHashResult.Size = new Size(1232, 23);
            panelMD5VerifyHashResult.TabIndex = 7;
            // 
            // textMD5VerifyHash
            // 
            textMD5VerifyHash.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            textMD5VerifyHash.Location = new Point(0, 1);
            textMD5VerifyHash.Margin = new Padding(4);
            textMD5VerifyHash.Name = "textMD5VerifyHash";
            textMD5VerifyHash.Size = new Size(1000, 27);
            textMD5VerifyHash.TabIndex = 7;
            // 
            // labelMD5VerifyResult
            // 
            labelMD5VerifyResult.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            labelMD5VerifyResult.AutoSize = true;
            labelMD5VerifyResult.Location = new Point(1010, 5);
            labelMD5VerifyResult.Margin = new Padding(4, 0, 4, 0);
            labelMD5VerifyResult.Name = "labelMD5VerifyResult";
            labelMD5VerifyResult.Size = new Size(88, 20);
            labelMD5VerifyResult.TabIndex = 9;
            labelMD5VerifyResult.Text = "验证结果:";
            // 
            // MD5TabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(mainTableLayout);
            Margin = new Padding(4);
            Name = "MD5TabControl";
            Size = new Size(1278, 850);
            mainTableLayout.ResumeLayout(false);
            groupBoxMD5Hash.ResumeLayout(false);
            tableLayoutMD5Hash.ResumeLayout(false);
            tableLayoutMD5Hash.PerformLayout();
            panelMD5HashControls.ResumeLayout(false);
            panelMD5HashControls.PerformLayout();
            groupBoxMD5File.ResumeLayout(false);
            tableLayoutMD5File.ResumeLayout(false);
            tableLayoutMD5File.PerformLayout();
            panelMD5FileControls.ResumeLayout(false);
            panelMD5FileControls.PerformLayout();
            panelMD5FilePath.ResumeLayout(false);
            panelMD5FilePath.PerformLayout();
            panelMD5FileHash.ResumeLayout(false);
            panelMD5FileHash.PerformLayout();
            groupBoxMD5Verify.ResumeLayout(false);
            tableLayoutMD5Verify.ResumeLayout(false);
            tableLayoutMD5Verify.PerformLayout();
            panelMD5VerifyControls.ResumeLayout(false);
            panelMD5VerifyControls.PerformLayout();
            panelMD5VerifyHashResult.ResumeLayout(false);
            panelMD5VerifyHashResult.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private TableLayoutPanel mainTableLayout;
        private GroupBox groupBoxMD5Hash;
        private TableLayoutPanel tableLayoutMD5Hash;
        private Panel panelMD5HashControls;
        private Label labelMD5DataFormat;
        private ComboBox comboMD5DataFormat;
        private Label labelMD5OutputFormat;
        private ComboBox comboMD5OutputFormat;
        private Label label1;
        private TextBox textMD5Input;
        private Label label2;
        private TextBox textMD5Output;
        private Button btnMD5Hash;
        private Button btnMD5Clear;
        private GroupBox groupBoxMD5File;
        private TableLayoutPanel tableLayoutMD5File;
        private Panel panelMD5FileControls;
        private Label labelMD5FileHashFormat;
        private ComboBox comboMD5FileHashFormat;
        private Label label3;
        private Panel panelMD5FilePath;
        private TextBox textMD5FilePath;
        private Button btnMD5SelectFile;
        private Label label4;
        private Panel panelMD5FileHash;
        private TextBox textMD5FileHash;
        private Button btnMD5ComputeFileHash;
        private GroupBox groupBoxMD5Verify;
        private TableLayoutPanel tableLayoutMD5Verify;
        private Panel panelMD5VerifyControls;
        private Label labelMD5VerifyDataFormat;
        private ComboBox comboMD5VerifyDataFormat;
        private Label labelMD5VerifyHashFormat;
        private ComboBox comboMD5VerifyHashFormat;
        private Label label5;
        private TextBox textMD5VerifyData;
        private Label label6;
        private Panel panelMD5VerifyHashResult;
        private TextBox textMD5VerifyHash;
        private Button btnMD5Verify;
        private Label labelMD5VerifyResult;
    }
}