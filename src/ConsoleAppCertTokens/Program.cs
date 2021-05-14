using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using DomainLogicWrapper;

namespace ConsoleAppCertTokens
{
    class Program
    {
        static bool IsImportRootCertificates = false; //todo

        private static readonly ManagedModuleManager _moduleManager = new ManagedModuleManager();

        private static ManagedModule[] _modules = new ManagedModule[0];

        private static readonly ManagedCertificateManager _certificateManager = new ManagedCertificateManager();
        private static object _tokensLock=new object();
        public static ObservableCollection<Token> Tokens { get; set; }=new ObservableCollection<Token>();

        //private static PcscPoller _poller;
        private static readonly string certFile = @"localhost.pfx";
        private static string _tokenPin="12345678";

        static void Main(string[] args)
        {
            Console.WriteLine("start");
            //_poller=new PcscPoller();
            _modules = _moduleManager.listAllModules();
            foreach (var managedModule in _modules)
            {
                Console.WriteLine(managedModule.getInformation().SerialNumber);
            }
            UpdateTokenList();
            int validTokenIndex = 0;
            for (var i = 0; i < Tokens.Count; i++)
            {
                var token = Tokens[i];
                if (token.Type == ManagedTokenTypes.VALID || token.Type == ManagedTokenTypes.FIPS)
                {
                    validTokenIndex = i;
                    LoadCertificateList(Tokens[i], i);
                }
            }

            Console.WriteLine("writing");
            TokenAutoLogin(validTokenIndex);
            AddCertificates(certFile, validTokenIndex);
            _modules[validTokenIndex].deauthenticate();
            Tokens[validTokenIndex].IsLoggedIn = false;
            Console.WriteLine("done");
            Console.ReadLine();
        }

        private static void UpdateTokenList()
        {
            //string selectedTokenId = GetSelectedTokenId();
            //ObservableCollection<Token> observableCollection = new ObservableCollection<Token>(Tokens);
            ManagedTokenInfo[] newTokenInfoList = CreateTokenInfoFromModules();
            {
                lock (_tokensLock)
                {
                    ObservableCollection<Token> observableCollection2 = CreateTokensFromInfoList(newTokenInfoList);
                    foreach (Token token2 in observableCollection2)
                    {
                        if (token2.Type == ManagedTokenTypes.VALID || token2.Type == ManagedTokenTypes.FIPS)
                        {
                            //Token token3 = Tokens.FirstOrDefault((Token x) => x.Id == token2.Id);
                            //if (token3 != null)
                            //{
                            //    token2.Certificates = token3.Certificates;
                            //    token2.CertificateInfoListOnToken = token3.CertificateInfoListOnToken;
                            //}
                        }
                    }
                    Tokens.Clear();
                    Tokens = observableCollection2;
                }
            }
            //if (observableCollection.Count > newTokenInfoList.Length)
            //{
            //    RemoveCertificateInfoCollectionFromMatrix(observableCollection.Select((Token token) => token.Id).ToList(), newTokenInfoList);
            //}
            //SetTokensLoggedInState(observableCollection);
            //SetSelectedTokenIndex(selectedTokenId);
            //TokenAutoLogin();
        }

        
        private static ManagedTokenInfo[] CreateTokenInfoFromModules()
        {
            ManagedTokenInfo[] array = new ManagedTokenInfo[_modules.Length];
            for (int i = 0; i < _modules.Length; i++)
            {
                array[i] = _modules[i].getInformation();
                if (!VerifyTokenInfo(array[i]))
                {
                    throw new Exception("Incomplete information");
                }
            }
            return array;
        }

        private static bool VerifyTokenInfo(ManagedTokenInfo tokenInfo)
        {
            if (ManagedTokenTypes.FIPS != tokenInfo.Type && tokenInfo.Type != 0)
            {
                return true;
            }
            if (string.IsNullOrEmpty(tokenInfo.Label) || string.IsNullOrEmpty(tokenInfo.ReaderName) || string.IsNullOrEmpty(tokenInfo.SerialNumber))
            {
                return false;
            }
            return true;
        }

        private static ObservableCollection<Token> CreateTokensFromInfoList(ManagedTokenInfo[] infoList)
        {
            ObservableCollection<Token> observableCollection = new ObservableCollection<Token>();
            for (int i = 0; i < infoList.Length; i++)
            {
                Token token = CreateTokenFromInfo(infoList[i]);
                token.IsPresent = _modules[i].hasToken();
                //token.TypeIcon = (token.IsPresent ? GetTokenIcon(infoList[i].Type) : GetTokenLessIcon());
                UpdateTokenDisplayName(token);
                observableCollection.Add(token);
            }
            return observableCollection;
        }
        private static void UpdateTokenDisplayName(Token token)
        {
            string tokenName = GetTokenName(token);
            string text = token.ReaderName + Environment.NewLine + "   " + tokenName;
            token.DisplayName = text;// ((ModuleListViewOption == 0) ? tokenName : text) + GetFipsModeDisplayName(token);
            token.Label = tokenName;
        }
        private static Token CreateTokenFromInfo(ManagedTokenInfo info)
        {
            Token token = new Token();
            token.DisplayName = string.Empty;
            token.ReaderName = info.ReaderName;
            token.Label = info.Label;
            token.Type = info.Type;
            //token.TypeIcon = null;
            token.Id = info.SerialNumber;
            token.IsPinChangeNeeded = info.IsPinChangeNeeded;
            token.IsPresent = false;
            return token;
        }

        private static string GetTokenName(Token token)
        {
            if (token.Type == ManagedTokenTypes.VALID || token.Type == ManagedTokenTypes.FIPS)
            {
                return token.Label;
            }

            return "Unknown";// token.IsPresent ? GetTokenLabel(token.Type) : GetResourceString("Text_No_Smart_Card_Present");
        }

        public static async void LoadCertificateList(Token selectedToken, int TokenIndex)
        {
            //CertificateListStatus = GetResourceString("Text_Loading_Certificates");
            //CertificateInfoCollection selectedCertificateInfoCollection = CertificateInfoMatrix.FirstOrDefault((CertificateInfoCollection x) => x.Id == selectedToken.Id);
            //if (selectedCertificateInfoCollection != null)
            //{
            //    DisplayCertificateInfoList(selectedCertificateInfoCollection.CertificateInfoList);
            //    return;
            //}
            try
            {
                await LoadCertificatesFromModule(TokenIndex);
                //FinalizeLoadCertificateOperation();
            }
            catch (Exception)
            {
                //FinalizeLoadCertificateOperation();
            }
        }

        private static async Task LoadCertificatesFromModule(int TokenIndex)
        {
            try
            {
                //await Task.Factory.StartNew(delegate
                {
                    //InitializeLoadCertificateOperation();
                    Tokens[TokenIndex].Certificates = _certificateManager.loadCertificates(ref _modules[TokenIndex]).ToList();
                    DisplayCertificateList(TokenIndex);
                }//, _tokenSource.Token);
            }
            catch (ManagedModuleInactiveException)
            {
                //SetExceptionMessage(GetResourceString("Text_Exception_ModuleInactive"));
            }
            catch (ManagedModuleDeviceProblemException)
            {
            }
            catch (ManagedModuleException ex3)
            {
                //SetExceptionMessage(string.Format(GetResourceString("Format_Exception_ErrorCode"), ex3.ErrorCode));
            }
            catch (Exception ex4)
            {
                //SetExceptionMessage(GetResourceString("Text_Exception_UnhandledSystemException") + ex4.Message);
            }
            //await ShowErrorMessageBox(GetResourceString("Text_Certificate_Load"));
        }

        private static void DisplayCertificateList(int TokenIndex)
        {
            Collection<X509Certificate2> collection = new Collection<X509Certificate2>();
            if (TokenIndex < 0 || Tokens[TokenIndex].Certificates == null)
            {
                return;
            }
            foreach (ManagedCertificate certificate in Tokens[TokenIndex].Certificates)
            {
                var item = RawDataToCertificate(certificate.Value);
                collection.Add(item);
                Console.WriteLine("Certificate: " + item.Subject);
            }
            //UpdateCertificateInfoMatrix(collection, Tokens[TokenIndex]);
            //SetIsSelectAllCertificatesEnabled();
        }
        public static X509Certificate2 RawDataToCertificate(byte[] rawData)
        {
            X509Certificate2 x509Certificate = new X509Certificate2();
            x509Certificate.Import(rawData);
            return x509Certificate;
        }

        /////////===================
        private static void TokenAutoLogin(int tokenIndex)
        {
            try
            {
                int i;
                //for (i = 0; i < _modules.Length; i++)
                {
                    i = tokenIndex;
                    Token token = Tokens.FirstOrDefault((Token x) => x.Id == _modules[i].getInformation().SerialNumber);
                    //if (token != null && token.IsLoggedIn)
                    {
                        //TokenAuthenticator tokenAuthenticator = new TokenAuthenticator(ref _modules[i]);
                        var pin = new SecureString();
                        for (var i1 = 0; i1 < _tokenPin.Length; i1++)
                        {
                            pin.AppendChar(_tokenPin[i1]);
                        }

                        var authenticationCode = SecureStringToByteArray(pin);
                        _modules[tokenIndex].authenticateUser(ref authenticationCode);
                        token.Pin = pin;
                        token.IsLoggedIn = true;
                        Array.Clear(authenticationCode, 0, _tokenPin.Length);
                        //tokenAuthenticator.Execute(token.Pin);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                //SetExceptionMessage(GetResourceString("Text_Exception_UnhandledSystemException") + ex.Message);
            }
        }
        private static byte[] SecureStringToByteArray(SecureString input)
        {
            IntPtr intPtr = Marshal.SecureStringToGlobalAllocAnsi(input);
            try
            {
                byte[] array = new byte[input.Length];
                Marshal.Copy(intPtr, array, 0, input.Length);
                return array;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocAnsi(intPtr);
            }
        }

        public static async void AddCertificates(string fileName, int TokenIndex)
        {
            //InitializeAddCertificateOperation();
            try
            {
                CertificateType certType = GetCertificateType(fileName);
                byte[] certificateRawData = GetCertificateRawData(fileName);
                await AddCertificatesToToken(certType, certificateRawData, TokenIndex);
            }
            catch (ManagedCertificateInvalidKeySizeException)
            {
                //SetExceptionMessage(GetResourceString("Text_Exception_CertificateKeysInvalid"));
            }
            catch (ManagedModuleInactiveException)
            {
                //SetExceptionMessage(GetResourceString("Text_Exception_ModuleInactive"));
            }
            catch (ManagedModuleMemoryFullException mex)
            {
                Console.WriteLine(mex);
                //SetExceptionMessage(GetResourceString("Text_Exception_MemoryFull"));
            }
            catch (ManagedModuleDeviceProblemException)
            {
                //SetExceptionMessage(GetResourceString("Text_Exception_DeviceError"));
            }
            catch (ManagedModuleException ex5)
            {
                //SetExceptionMessage(string.Format(GetResourceString("Format_Exception_ErrorCode"), ex5.ErrorCode));
            }
            catch (CryptographicException e)
            {
                //SetExceptionMessage(ParseAddCertificateError(e));
            }
            //FinalizeAddCertificateOperation();
            //await ShowErrorMessageBox(GetResourceString("Text_Error_Certificate_Import_Failed"));
        }

        private static async Task AddCertificatesToToken(CertificateType certType, byte[] certificateRawData, int TokenIndex)
        {
            if (certType == CertificateType.P12 || certType == CertificateType.Pfx)
            {
                await AddPfxP12CertificatesToToken(certificateRawData, TokenIndex);
            }
            else
            {
                await AddCerP7CertificatesToToken(certificateRawData, certType, TokenIndex);
            }
        }

        private static CertificateType GetCertificateType(string fileName)
        {
            string extension = Path.GetExtension(fileName);
            extension = extension.TrimStart('.');
            extension = extension.ToUpper();

            //todo pfx
            return CertificateType.Pfx;
        }

        public static byte[] GetCertificateRawData(string fileName)
        {
            FileStream fileStream = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            byte[] array = new byte[(int)fileStream.Length];
            int num = 0;
            int num2 = (int)fileStream.Length;
            while (num2 > 0)
            {
                int num3 = fileStream.Read(array, num, num2);
                if (num3 <= 0)
                {
                    break;
                }
                num2 -= num3;
                num += num3;
            }
            fileStream.Close();
            return array;
        }

        private static async Task AddPfxP12CertificatesToToken(byte[] certificateRawData, int TokenIndex)
        {
            SecureString securePassword = new SecureString();
            var pass = "12345678";
            for (var i = 0; i < pass.Length; i++)
            {
                securePassword.AppendChar(pass[i]);
            }
            if (securePassword == null)
            {
                return;
            }
            //ShowCertificateProgressRing(GetResourceString("Text_Certificate_Add_Progress"));
            ICollection<X509Certificate2> certificates = CreateCertificatesFromRawData(certificateRawData, securePassword);
            if (certificates.Count != 0)
            {
                //await Task.Factory.StartNew(delegate
                {
                    AddCertificateToToken(certificateRawData, ref securePassword, TokenIndex);
                    //UpdateCertificateInfoMatrix(certificates, Tokens[_tokenIndex]);
                }//);
            }
        }
        private static void AddCertificateToToken(byte[] certificateRawData, ref SecureString securePassword, int TokenIndex)
        {
            ManagedCertificate[] array = _certificateManager.addCertificate(ref _modules[TokenIndex], ref certificateRawData, ref securePassword, IsImportRootCertificates);
            ManagedCertificate[] array2 = array;
            foreach (ManagedCertificate item in array2)
            {
                Tokens[TokenIndex].Certificates.Add(item);
            }
        }
        private static async Task AddCerP7CertificatesToToken(byte[] certificateRawData, CertificateType certType,
            int TokenIndex)
        {
            //ShowCertificateProgressRing(GetResourceString("Text_Certificate_Add_Progress"));
            ICollection<X509Certificate2> certificates = CreateCertificatesFromRawData(certificateRawData, certType);
            if (certificates.Count != 0)
            {
                await Task.Factory.StartNew(delegate
                {
                    AddCertificateToToken(certificateRawData, GetImportOption(certType), TokenIndex);
                    //UpdateCertificateInfoMatrix(certificates, Tokens[TokenIndex]);
                });
            }
        }
        private static void AddCertificateToToken(byte[] certificateRawData, byte importOption, int TokenIndex)
        {
            ManagedCertificate[] array = _certificateManager.addCertificate(ref _modules[TokenIndex], ref certificateRawData, importOption);
            ManagedCertificate[] array2 = array;
            foreach (ManagedCertificate item in array2)
            {
                Tokens[TokenIndex].Certificates.Add(item);
            }
        }
        public static byte GetImportOption(CertificateType certType)
        {
            byte b = 0;
            if (IsImportRootCertificates)
            {
                b = 1;
            }
            if (CertificateType.P7B == certType || CertificateType.P7C == certType)
            {
                b = (byte)(b | 2u);
            }
            return b;
        }
        public static ICollection<X509Certificate2> CreateCertificatesFromRawData(byte[] rawData, SecureString password)
        {
            X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
            x509Certificate2Collection.Import(rawData, ConvertToUnsecureString(password), X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            Collection<X509Certificate2> collection = new Collection<X509Certificate2>();
            X509Certificate2 userCertificate = GetUserCertificate(x509Certificate2Collection);
            if (!IsImportRootCertificates && userCertificate != null)
            {
                collection.Add(userCertificate);
                return collection;
            }
            X509Certificate2Enumerator enumerator = x509Certificate2Collection.GetEnumerator();
            while (enumerator.MoveNext())
            {
                X509Certificate2 current = enumerator.Current;
                collection.Add(current);
            }
            return collection;
        }
        public static ICollection<X509Certificate2> CreateCertificatesFromRawData(byte[] rawData, CertificateType certType)
        {
            Collection<X509Certificate2> collection = new Collection<X509Certificate2>();
            switch (certType)
            {
                case CertificateType.Cer:
                    collection.Add(CreateCerTypeCertificate(rawData));
                    break;
                case CertificateType.P7B:
                case CertificateType.P7C:
                    collection = CreateP7TypeCertificates(rawData) as Collection<X509Certificate2>;
                    break;
            }
            return collection;
        }
        private static X509Certificate2 CreateCerTypeCertificate(byte[] rawData)
        {
            X509Certificate2 x509Certificate = new X509Certificate2();
            x509Certificate.Import(rawData);
            return x509Certificate;
        }
        private static ICollection<X509Certificate2> CreateP7TypeCertificates(byte[] rawData)
        {
            Collection<X509Certificate2> collection = new Collection<X509Certificate2>();
            SignedCms signedCms = new SignedCms();
            signedCms.Decode(rawData);
            X509Certificate2 userCertificate = GetUserCertificate(signedCms.Certificates);
            if (!IsImportRootCertificates && userCertificate != null)
            {
                collection.Add(userCertificate);
                return collection;
            }
            X509Certificate2Enumerator enumerator = signedCms.Certificates.GetEnumerator();
            while (enumerator.MoveNext())
            {
                X509Certificate2 current = enumerator.Current;
                collection.Add(current);
            }
            return collection;
        }

        private static X509Certificate2 GetUserCertificate(X509Certificate2Collection certificates)
        {
            new X509Certificate2();
            X509Certificate2Enumerator enumerator = certificates.GetEnumerator();
            while (enumerator.MoveNext())
            {
                X509Certificate2 current = enumerator.Current;
                if (!IsCaCertificate(current))
                {
                    return current;
                }
            }
            return null;
        }

        private static bool IsCaCertificate(X509Certificate2 certificate)
        {
            if (IsSelfSigned(certificate))
            {
                return true;
            }
            X509BasicConstraintsExtension basicConstraints = GetBasicConstraints(certificate);
            if (basicConstraints != null && basicConstraints.CertificateAuthority)
            {
                return true;
            }
            return false;
        }
        private static bool IsSelfSigned(X509Certificate2 certificate)
        {
            return certificate.SubjectName.RawData.SequenceEqual(certificate.IssuerName.RawData);
        }
        private static X509BasicConstraintsExtension GetBasicConstraints(X509Certificate2 certificate)
        {
            X509ExtensionEnumerator enumerator = certificate.Extensions.GetEnumerator();
            while (enumerator.MoveNext())
            {
                X509Extension current = enumerator.Current;
                if (current.Oid.FriendlyName == "Basic Constraints")
                {
                    return current as X509BasicConstraintsExtension;
                }
            }
            return null;
        }

        public static string ConvertToUnsecureString(SecureString securePassword)
        {
            IntPtr intPtr = IntPtr.Zero;
            try
            {
                intPtr = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
                return Marshal.PtrToStringUni(intPtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(intPtr);
            }
        }
    }

    internal class Token
    {
        public string DisplayName { get; set; }
        public string ReaderName { get; set; }
        public string Label { get; set; }
        public ManagedTokenTypes Type { get; set; }
        public string Id { get; set; }
        public bool IsPinChangeNeeded { get; set; }
        public bool IsPresent { get; set; }
        public List<ManagedCertificate> Certificates { get; set; }
        public bool IsLoggedIn { get; set; }
        public SecureString Pin { get; set; }
        //public string Pin { get; set; }
    }
    public enum CertificateType
    {
        Cer,
        Pfx,
        P12,
        P7B,
        P7C
    }
}
