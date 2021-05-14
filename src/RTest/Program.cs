using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace RTest
{
    class Program
    {
        private static string _pin = "12345678";
        private static string pass="12345678";

        static void Main(string[] args)
        {
            try
            {
                Test();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                
            }

            Console.WriteLine("Done...");
            Console.ReadLine();
        }

        static void Test()
        {
            string pkcs11LibraryPath = null;
            var logFilePath = @"d:\pkcs11-logger-x64.log";
            string loggerLibraryPath;
            if (Net.Pkcs11Interop.Common.Platform.Uses64BitRuntime)
            {
                pkcs11LibraryPath = @"acos5evopkcs11.dll";
                loggerLibraryPath = @"pkcs11-logger-x64.dll";
            }
            else
            {
                pkcs11LibraryPath = @"acos5evopkcs11.dll";
                loggerLibraryPath = @"pkcs11-logger-x86.dll";
            }

            System.Environment.SetEnvironmentVariable("PKCS11_LOGGER_LIBRARY_PATH", pkcs11LibraryPath);
            System.Environment.SetEnvironmentVariable("PKCS11_LOGGER_LOG_FILE_PATH", logFilePath);
            System.Environment.SetEnvironmentVariable("PKCS11_LOGGER_FLAGS", "64");


            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            using (IPkcs11Library pkcs11Library =
                factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, loggerLibraryPath, AppType.MultiThreaded))
            {
                // Do something interesting
                ISlot slot = GetUsableSlot(pkcs11Library);

                // Open RW session
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, _pin);


                    var ss = new SecureString();
                    for (var i = 0; i < pass.Length; i++)
                    {
                        ss.AppendChar(pass[i]);
                    }

                    var certBytes = File.ReadAllBytes("localhost.pfx");
                    X509Certificate2 cert = new X509Certificate2(certBytes, ss, X509KeyStorageFlags.Exportable);
                    var bCert = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(cert);
                    var encodedCert = bCert.GetEncoded();

                    var privateKeyParams = cert.GetRSAPrivateKey().ExportParameters(true);

                    var unencryptedPrivateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(
                        new RsaPrivateCrtKeyParameters(
                            new BigInteger(1, privateKeyParams.Modulus),
                            new BigInteger(1, privateKeyParams.Exponent),
                            new BigInteger(1, privateKeyParams.D),
                            new BigInteger(1, privateKeyParams.P),
                            new BigInteger(1, privateKeyParams.Q),
                            new BigInteger(1, privateKeyParams.DP),
                            new BigInteger(1, privateKeyParams.DQ),
                            new BigInteger(1, privateKeyParams.InverseQ))).GetEncoded();

                    IObjectHandle tempKey = GenerateKey(session);
                    byte[] iv = session.GenerateRandom(8);

                    var result = new MemoryStream();
                    var mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_DES3_CBC_PAD, iv);
                    session.Encrypt(mechanism, tempKey, new MemoryStream(unencryptedPrivateKey), result);
                    var encryptedPrivateKey = result.ToArray();

                    WriteCert(session, encodedCert, cert, bCert);
                    
                    session.Logout();
                }

            }
        }

        private static void WriteCert(ISession session, byte[] encodedCert, X509Certificate2 cert,
            X509Certificate bCert)
        {
            RSAParameters privateKeyParamsNet;
            privateKeyParamsNet = cert.GetRSAPrivateKey().ExportParameters(true);
            //Org.BouncyCastle.Security.DotNetUtilities.ToRSA(privateKeyParamsNet)

            var cn = cert.Subject.ToString();
            //var cn2 = cert.SubjectName.Name;
            byte[] thumbPrint = null;
            using (SHA1Managed sha1Managed = new SHA1Managed())
                thumbPrint = sha1Managed.ComputeHash(cert.RawData);

            //var pair = DotNetUtilities.GetRsaKeyPair(privateKeyParamsNet);
            //var pair2 = DotNetUtilities.GetRsaPublicKey(privateKeyParamsNet);
            //AsymmetricKeyParameter pairPrivate;
            //pairPrivate = pair.Private;

            var privateKeyParams = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, privateKeyParamsNet.Modulus),
                new BigInteger(1, privateKeyParamsNet.Exponent),
                new BigInteger(1, privateKeyParamsNet.D),
                new BigInteger(1, privateKeyParamsNet.P),
                new BigInteger(1, privateKeyParamsNet.Q),
                new BigInteger(1, privateKeyParamsNet.DP),
                new BigInteger(1, privateKeyParamsNet.DQ),
                new BigInteger(1, privateKeyParamsNet.InverseQ));
            var unencryptedPrivateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParams)
                .GetEncoded();
            //var privateKeyParams = pairPrivate;

            //var result = new MemoryStream();
            //byte[] iv={0,0,0,0};
            //List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_DATA));

            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, thumbPrint));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, cn));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));//true
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));//true
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, privateKeyParamsNet.Modulus));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, privateKeyParamsNet.Exponent));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE_EXPONENT, privateKeyParamsNet.D));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_1, privateKeyParamsNet.P));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_2, privateKeyParamsNet.Q));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_1, privateKeyParamsNet.DP));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_2, privateKeyParamsNet.DQ));
            //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COEFFICIENT, privateKeyParamsNet.InverseQ));

            var privateKeyAttributes = new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, cn),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, thumbPrint),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS, privateKeyParams.Modulus.ToByteArrayUnsigned()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, privateKeyParams.PublicExponent.ToByteArrayUnsigned()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE_EXPONENT, privateKeyParams.Exponent.ToByteArrayUnsigned()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_1, privateKeyParams.P.ToByteArrayUnsigned()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIME_2, privateKeyParams.Q.ToByteArrayUnsigned()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_1, privateKeyParams.DP.ToByteArrayUnsigned()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXPONENT_2, privateKeyParams.DQ.ToByteArrayUnsigned()),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COEFFICIENT, privateKeyParams.QInv.ToByteArrayUnsigned())
            };


            List<IObjectAttribute> certificateAttributes = new List<IObjectAttribute>();
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, cn));// privKeyAttributes[0].GetValueAsString()));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TRUSTED, false));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SUBJECT, bCert.SubjectDN.GetDerEncoded()));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, thumbPrint));//Encoding.ASCII.GetBytes(cn)));// privKeyAttributes[1].GetValueAsByteArray()));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ISSUER, bCert.IssuerDN.GetDerEncoded()));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SERIAL_NUMBER, new DerInteger(bCert.SerialNumber).GetDerEncoded()));
            certificateAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, bCert.GetEncoded()));

            IMechanism mechanism1 = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

            // Generate key pair
            session.GenerateKeyPair(mechanism1, certificateAttributes, privateKeyAttributes, out var publicKeyHandle, out var privateKeyHandle1);
            
            //var privateKeyHandle2 = session.CreateObject(privateKeyAttributes);

            // Generate random initialization vector
            //// Create temporary DES3 key for wrapping/unwrapping
            //var tempKeyAttributes = new List<IObjectAttribute>();
            //tempKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
            //tempKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3));
            //tempKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
            //tempKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));

            //var tempKey = session.GenerateKey(session.Factories.MechanismFactory.Create(CKM.CKM_DES3_KEY_GEN), tempKeyAttributes);
            IObjectHandle generatedKey = GenerateKey(session);
            byte[] iv = session.GenerateRandom(8);

            

            //IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_DES3_CBC, iv);
            IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);

            byte[] wrappedKey = session.WrapKey(mechanism, generatedKey, privateKeyHandle1);

            // Define attributes for unwrapped key
            List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "unwrapped_private"));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true));

            // Unwrap private key
            var unwrappedKey = session.UnwrapKey(mechanism, generatedKey, wrappedKey, objectAttributes);


            //byte[] encryptedPrivateKey = session.Encrypt(mechanism, generatedKey, unencryptedPrivateKey);
            //session.WrapKey(mechanism, , generatedKey);
            //var result = new MemoryStream();
            ////session.Encrypt(session.Factories.MechanismFactory.Create(CKM.CKM_DES3_CBC_PAD, iv), tempKey, new MemoryStream(unencryptedPrivateKey), result);
            //var encryptedPrivateKey = result.ToArray();

            //var privateKeyHandle = session.CreateObject(privateKeyAttributes);

            //var privateKeyHandle = session.UnwrapKey(session.Factories.MechanismFactory.Create(CKM.CKM_DES3_CBC_PAD, iv), generatedKey, encryptedPrivateKey, privateKeyAttributes);


        }

        public static IObjectHandle GenerateKey(ISession session)
        {
            // Prepare attribute template of new key
            List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true));
            objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true));

            // Specify key generation mechanism
            IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_DES3_KEY_GEN);

            // Generate key
            return session.GenerateKey(mechanism, objectAttributes);
        }

        public static ISlot GetUsableSlot(IPkcs11Library pkcs11Library)
        {
            // Get list of available slots with token present
            List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

            // First slot with token present is OK...
            ISlot matchingSlot = slots[0];

            // ...unless there are matching criteria specified in Settings class
            {
                matchingSlot = null;

                foreach (ISlot slot in slots)
                {
                    ITokenInfo tokenInfo = null;

                    try
                    {
                        tokenInfo = slot.GetTokenInfo();
                    }
                    catch (Pkcs11Exception ex)
                    {
                        if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                            throw;
                    }

                    if (tokenInfo == null)
                        continue;

                    matchingSlot = slot;
                    break;
                }
            }

            return matchingSlot;
        }

    }
}
