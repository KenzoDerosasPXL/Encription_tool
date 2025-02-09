using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Forms;
using System.Windows.Media.Imaging;
using System.Xml;
using System.Xml.Linq;
using MessageBox = System.Windows.MessageBox;

namespace Encription_tool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private FolderBrowserDialog AESdialog;
        private FolderBrowserDialog AESEncryptedDialog;
        private FolderBrowserDialog RSAdialog;

        private BitmapImage? image = null;

        private string EncryptedImage;
        private string EncryptedAESKey;
        private string AESKeyTemp;

        public Dictionary<string, string> AESKeyList = new();
        public Dictionary<string, string> AESEncryptedKeyList = new();

        public Dictionary<string, string> RSAPrivateKeyList = new();
        public Dictionary<string, string> RSAPublicKeyList = new();

        private void btnSelectAESKeyFolder_Click(object sender, RoutedEventArgs e)
        {
            lstbAESKey.ItemsSource = AESKeyList;
            lstbAESKey.DisplayMemberPath = "Key";
            lstbAESKey.SelectedValuePath = "Value";

            lstbAESKeys.ItemsSource = AESKeyList;
            lstbAESKeys.DisplayMemberPath = "Key";
            lstbAESKeys.SelectedValuePath = "Value";

            using (AESdialog = new FolderBrowserDialog())
            {
                DialogResult result = AESdialog.ShowDialog();
                if (result.ToString() == "OK")
                {
                    AESKeyList.Clear();
                    foreach (string file in Directory.EnumerateFiles(AESdialog.SelectedPath, "*.key"))
                    {
                        AESKeyList.Add(file.Split(@"\")[^1], File.ReadAllText(file));
                    }
                }
            }
        }

        private void btnSelectEncryptedAESKeyFolder_Click(object sender, RoutedEventArgs e)
        {
            lstbEncryptedAESKeys.ItemsSource = AESEncryptedKeyList;
            lstbEncryptedAESKeys.DisplayMemberPath = "Key";
            lstbEncryptedAESKeys.SelectedValuePath = "Value";

            using (AESEncryptedDialog = new FolderBrowserDialog())
            {
                DialogResult result = AESEncryptedDialog.ShowDialog();
                if (result.ToString() == "OK")
                {
                    AESEncryptedKeyList.Clear();
                    foreach (string file in Directory.EnumerateFiles(AESEncryptedDialog.SelectedPath, "*.txt"))
                    {
                        AESEncryptedKeyList.Add(file.Split(@"\")[^1], File.ReadAllText(file));
                    }
                }
            }
        }

        private void btnSelectRSAKeyFolder_Click(object sender, RoutedEventArgs e)
        {
            lstbRSAPrivateKey.ItemsSource = RSAPrivateKeyList;
            lstbRSAPrivateKey.DisplayMemberPath = "Key";
            lstbRSAPrivateKey.SelectedValuePath = "Value";

            lstbRSAPublicKey.ItemsSource = RSAPublicKeyList;
            lstbRSAPublicKey.DisplayMemberPath = "Key";
            lstbRSAPublicKey.SelectedValuePath = "Value";

            using (RSAdialog = new FolderBrowserDialog())
            {
                DialogResult result = RSAdialog.ShowDialog();
                if (result.ToString() == "OK")
                {
                    string[] files = Directory.GetFiles(RSAdialog.SelectedPath, "*.xml");
                    RSAPrivateKeyList.Clear();
                    RSAPublicKeyList.Clear();
                    foreach (string filepath in files)
                    {
                        XElement po = XElement.Load(filepath);
                        string publicKey = po.Element("PublicKey").Value;
                        string privateKey = po.Element("PrivateKey").Value;
                        RSAPrivateKeyList.Add(Path.GetFileName(filepath), privateKey.ToString());
                        RSAPublicKeyList.Add(Path.GetFileName(filepath), publicKey.ToString());
                    }
                }
            }
        }

        #region Encrypt

        #region AES

        private byte[] AESkey = new byte[32]; // 32 bytes = 256 bits
        private byte[] AESiv = new byte[16]; // 16 bytes = 128 bits

        private void btnAESGenerateKey_Click(object sender, RoutedEventArgs e)
        {
            string completeKey = GenerateAESKey();
            string fileName;
            if (AESdialog != null)
            {
                if (string.IsNullOrEmpty(txtKeyFileName.Text))
                {
                    fileName = AESdialog.SelectedPath + $@"\AESKey_{DateTime.Now.ToFileTime()}.key";
                }
                else
                {
                    fileName = AESdialog.SelectedPath + $@"\{txtKeyFileName.Text}.key";
                }
                FileInfo fi = new(fileName);
                if (Directory.Exists(AESdialog.SelectedPath))
                {
                    using (FileStream fs = fi.Create())
                    {
                        Byte[] txt = new UTF8Encoding(true).GetBytes(completeKey);
                        fs.Write(txt, 0, txt.Length);
                    }
                    using (StreamReader sr = File.OpenText(fileName))
                    {
                        string s = "";
                        while ((s = sr.ReadLine()) != null)
                        {
                            AESKeyList.Add(fileName.Split(@"\")[^1], s);
                        }
                    }
                    MessageBox.Show("AES keys saved to " + AESdialog.SelectedPath + $@"\{txtKeyFileName.Text}.key");
                }
                else
                {
                    MessageBox.Show("Folder does not exist");
                }
            }
            else
            {
                MessageBox.Show("Select a folder for AES keys");
            }
        }

        private void btnAESImageEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (imgAES.Source != null)
            {
                if (lstbAESKey.SelectedIndex < 0)
                {
                    MessageBox.Show("Please select a AES key", "Error");
                }
                else
                {
                    string keyAndIv = lstbAESKey.SelectedValue.ToString();
                    AESiv = Convert.FromBase64String(keyAndIv.Split(",")[0]);
                    AESkey = Convert.FromBase64String(keyAndIv.Split(",")[1]);
                    txtEncryptedImageAES.Text = Convert.ToBase64String(EncryptStringToBytes_Aes(Convert.ToBase64String(getJPGFromImageControl(image)), AESkey, AESiv));
                    EncryptedImage = Convert.ToBase64String(EncryptStringToBytes_Aes(Convert.ToBase64String(getJPGFromImageControl(image)), AESkey, AESiv));
                    imgAES.Source = null;
                }
            }
            else
            {
                MessageBox.Show("No image selected", "Select image");
            }
        }

        private Bitmap dImg;

        private void btnAESImageDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(txtEncryptedImageAES.Text))
            {
                MessageBox.Show("Please provide a ciphertext", "No input");
            }
            else
            {
                if (lstbAESKey.SelectedIndex >= 0)
                {
                    try
                    {
                        string keyAndIv = lstbAESKey.SelectedValue.ToString();
                        AESiv = Convert.FromBase64String(keyAndIv.Split(",")[0]);
                        AESkey = Convert.FromBase64String(keyAndIv.Split(",")[1]);
                        byte[] cipherText = Convert.FromBase64String(txtEncryptedImageAES.Text);
                        txtEncryptedImageAES.Clear();
                        Image newImage;
                        byte[] image = Convert.FromBase64String(DecryptStringFromBytes_Aes(cipherText, AESkey, AESiv));
                        using (MemoryStream ms = new MemoryStream(image, 0, image.Length))
                        {
                            ms.Write(image, 0, image.Length);
                            newImage = Image.FromStream(ms, true);
                            dImg = new Bitmap(newImage);

                            MemoryStream mss = new MemoryStream();

                            dImg.Save(mss, ImageFormat.Jpeg);

                            BitmapImage bImg = new BitmapImage();

                            bImg.BeginInit();

                            bImg.StreamSource = new MemoryStream(ms.ToArray());

                            bImg.EndInit();
                            imgAES.Source = bImg;
                            // work with image here.
                            // You'll need to keep the MemoryStream open for
                            // as long as you want to work with your new image.
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.Message, "Error");
                    }
                }
                else
                {
                    MessageBox.Show("Please select a AES key", "Error");
                }
            }
        }

        private string GenerateAESKey()
        {
            Aes aesEncryption = Aes.Create();
            aesEncryption.Mode = CipherMode.CBC;
            aesEncryption.Padding = PaddingMode.PKCS7;
            aesEncryption.KeySize = 256;
            aesEncryption.BlockSize = 128;
            aesEncryption.GenerateKey();
            AESkey = aesEncryption.Key;
            aesEncryption.GenerateIV();
            AESiv = aesEncryption.IV;
            return Convert.ToBase64String(AESiv) + "," + Convert.ToBase64String(AESkey);
        }

        private static byte[] EncryptStringToBytes_Aes(string plaintext, byte[] key, byte[] iv)
        {
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException(nameof(iv));
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = 256;
                aesAlg.BlockSize = 128;
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);

                using (MemoryStream msEncrypt = new())
                {
                    using (CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                        csEncrypt.FlushFinalBlock();
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
            return encrypted;
        }

        private static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key, byte[] iv)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException(nameof(iv));
            string? plaintext = null;
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Key = key;
                aes.IV = iv;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using MemoryStream ms = new();
                using CryptoStream cs = new(ms, decryptor, CryptoStreamMode.Write);

                cs.Write(cipherText, 0, cipherText.Length);
                cs.FlushFinalBlock();

                //return Encoding.Unicode.GetString(ms.ToArray());

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new(cipherText))
                {
                    using (CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        #endregion AES

        #region RSA

        private void btnRSAGenerateKey_Click(object sender, RoutedEventArgs e)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            // Get the public and private key XML strings
            string publicKeyXml = rsa.ToXmlString(false);
            string privateKeyXml = rsa.ToXmlString(true);

            // Create the XML writer settings
            XmlWriterSettings settings = new()
            {
                Indent = true
            };

            string fileName;
            if (RSAdialog != null)
            {
                if (string.IsNullOrEmpty(txtKeyFileName.Text))
                {
                    fileName = RSAdialog.SelectedPath + $@"\RSAKey_{DateTime.Now.ToFileTime()}.xml";
                }
                else
                {
                    fileName = RSAdialog.SelectedPath + $@"\{txtKeyFileName.Text}.xml";
                }
                if (Directory.Exists(RSAdialog.SelectedPath))
                {
                    using (XmlWriter writer = XmlWriter.Create(fileName, settings))
                    {
                        writer.WriteStartElement("RSAKeys");

                        writer.WriteStartElement("PublicKey");
                        writer.WriteValue(publicKeyXml);
                        writer.WriteEndElement();

                        writer.WriteStartElement("PrivateKey");
                        writer.WriteValue(privateKeyXml);
                        writer.WriteEndElement();

                        writer.WriteEndElement();
                    }
                    MessageBox.Show("RSA keys saved to " + RSAdialog.SelectedPath + $@"\{txtKeyFileName.Text}.xml");
                }
                else
                {
                    MessageBox.Show("Folder does not exist");
                }
            }
            else
            {
                MessageBox.Show("Select a folder for RSA keys");
            }
        }

        private void btnRSAEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (lstbAESKeys.SelectedIndex >= 0)
            {
                string keyAndIv = lstbAESKeys.SelectedValue.ToString();
                string publicKey = lstbRSAPublicKey.SelectedValue.ToString();
                byte[] plainTextBytes = Encoding.UTF8.GetBytes(keyAndIv);

                using (var rsa = new RSACryptoServiceProvider(1024))
                {
                    try
                    {
                        // client encrypting data with public key issued by server
                        rsa.FromXmlString(publicKey.ToString());

                        var encryptedData = rsa.Encrypt(plainTextBytes, true);

                        EncryptedAESKey = Convert.ToBase64String(encryptedData);

                        SaveEncryptedAES();
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }
        }

        private void btnRSADecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (lstbEncryptedAESKeys.SelectedIndex >= 0)
            {
                string privateKey = lstbRSAPrivateKey.SelectedValue.ToString();

                using (var rsa = new RSACryptoServiceProvider(1024))
                {
                    try
                    {
                        var base64Encrypted = lstbEncryptedAESKeys.SelectedValue.ToString();

                        // server decrypting data with private key
                        rsa.FromXmlString(privateKey);

                        var resultBytes = Convert.FromBase64String(base64Encrypted);
                        var decryptedBytes = rsa.Decrypt(resultBytes, true);
                        AESKeyTemp = Encoding.UTF8.GetString(decryptedBytes);

                        SaveAES();
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }
        }

        private void SaveAES()
        {
            MessageBoxResult rsltMessageBox = MessageBox.Show("Do you want to save this AES key?", "Save Key", MessageBoxButton.YesNo);
            if (rsltMessageBox == MessageBoxResult.Yes)
            {
                Microsoft.Win32.SaveFileDialog dialog = new()
                {
                    Filter = "Key files (*.key)|*.key"
                };

                bool? result = dialog.ShowDialog();
                if (result == true)
                {
                    using (StreamWriter sw = File.CreateText(dialog.FileName))
                    {
                        sw.Write(AESKeyTemp);
                    }
                    MessageBox.Show("Successfully saved AES key", "Success");
                }
            }
        }

        private void SaveEncryptedAES()
        {
            MessageBoxResult rsltMessageBox = MessageBox.Show("Do you want to save this encrypted AES key?", "Save Key", MessageBoxButton.YesNo);
            if (rsltMessageBox == MessageBoxResult.Yes)
            {
                Microsoft.Win32.SaveFileDialog dialog = new()
                {
                    Filter = "Text files (*.txt)|*.txt"
                };

                bool? result = dialog.ShowDialog();
                if (result == true)
                {
                    using (StreamWriter sw = File.CreateText(dialog.FileName))
                    {
                        sw.Write(EncryptedAESKey);
                    }
                    MessageBox.Show("Successfully saved encrypted AES key", "Success");
                }
            }
        }

        #endregion RSA

        private void btnLoadImage_Click(object sender, RoutedEventArgs e)
        {
            System.Windows.Forms.OpenFileDialog op = new()
            {
                Title = "Select a picture",
                Filter = "All supported graphics|*.jpg;*.jpeg;" +
              "JPEG (*.jpg;*.jpeg)|*.jpg;*.jpeg|"
            };
            if (op.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                image = new BitmapImage(new Uri(op.FileName));
            }
            imgAES.Source = image;
        }

        public static byte[] getJPGFromImageControl(BitmapImage imageC)
        {
            MemoryStream memStream = new();
            JpegBitmapEncoder encoder = new();
            encoder.Frames.Add(BitmapFrame.Create(imageC));
            encoder.Save(memStream);
            return memStream.ToArray();
        }

        #endregion Encrypt

        private void btnSaveEncryptedImage_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(txtEncryptedImageAES.Text))
            {
                Microsoft.Win32.SaveFileDialog dialog = new()
                {
                    Filter = "Text files (*.txt)|*.txt"
                };

                bool? result = dialog.ShowDialog();
                if (result == true)
                {
                    using (StreamWriter sw = File.CreateText(dialog.FileName))
                    {
                        sw.Write(EncryptedImage);
                    }
                    MessageBox.Show("Successfully saved ciphertext", "Success");
                }
            }
            else
            {
                MessageBox.Show("No ciphertext found to encrypt", "Error");
            }
        }

        private void btnLoadCiphertext_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new Microsoft.Win32.OpenFileDialog() { Filter = "Text files (*.txt)|*.txt" };
            var result = ofd.ShowDialog();
            if (result == false) return;

            using StreamReader sr = new(ofd.FileName);
            String line = sr.ReadToEnd();
            txtEncryptedImageAES.Text = line;
        }

        private void btnSavePlainImage_Click(object sender, RoutedEventArgs e)
        {
            if (imgAES.Source == null)
            {
                MessageBox.Show("No image found to save", "Error");
            }
            else
            {
                Microsoft.Win32.SaveFileDialog dialog = new()
                {
                    Filter = "Images|*.jpg ; *.png "
                };
                ImageFormat format = ImageFormat.Jpeg;

                bool? result = dialog.ShowDialog();
                if (result == true)
                {
                    if (dialog.Filter == ".jpg")
                    {
                        format = ImageFormat.Png;
                    }
                    dImg.Save(dialog.FileName, format);
                }
            }
        }
    }
}