/*
 *  Pkcs11Interop.PDF - Integration layer for Pkcs11Interop 
 *                      and iText (iTextSharp) libraries
 *  Copyright (c) 2013-2017 JWC s.r.o. <http://www.jwc.sk>
 *  Author: Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  Licensing for open source projects:
 *  Pkcs11Interop.PDF is available under the terms of the GNU Affero General 
 *  Public License version 3 as published by the Free Software Foundation.
 *  Please see <http://www.gnu.org/licenses/agpl-3.0.html> for more details.
 *
 *  Licensing for other types of projects:
 *  Pkcs11Interop.PDF is available under the terms of flexible commercial license.
 *  Please contact JWC s.r.o. at <info@pkcs11interop.net> for more details.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using PemWriter = Org.BouncyCastle.Utilities.IO.Pem.PemWriter;

namespace Net.Pkcs11Interop.Cert
{
    /// <summary>
    /// Explores devices accessible via PKCS#11 interface
    /// </summary>
    public class Pkcs11Explorer : IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// High level PKCS#11 wrapper
        /// </summary>
        private Pkcs11 _pkcs11 = null;
        string pkcs11LibraryPath;

        /// <summary>
        /// Initializes a new instance of the Pkcs11Explorer class
        /// </summary>
        /// <param name="libraryPath">Path to the unmanaged PCKS#11 library</param>
        public Pkcs11Explorer(string libraryPath)
        {
            if (string.IsNullOrEmpty(libraryPath))
                throw new ArgumentNullException("libraryPath");

            try
            {
                _pkcs11 = new Pkcs11(libraryPath, true);
                //Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                if (Net.Pkcs11Interop.Common.Platform.Uses64BitRuntime)
                {
                    pkcs11LibraryPath = @"pkcs11-x64.dll";
                }
                else
                {
                    pkcs11LibraryPath = @"pkcs11-x86.dll";
                }
            }
            catch (Pkcs11Exception ex)
            {
                if (ex.RV == CKR.CKR_CANT_LOCK)
                    _pkcs11 = new Pkcs11(libraryPath, false);
                else
                    throw;
            }
        }

        /// <summary>
        /// Gets list of tokens (smartcards) accessible via PKCS#11 interface
        /// </summary>
        /// <returns></returns>
        public List<Token> GetTokens()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            List<Token> tokens = new List<Token>();

            List<Slot> slots = _pkcs11.GetSlotList(true);
            foreach (Slot slot in slots)
            {
                TokenInfo tokenInfo = null;

                try
                {
                    tokenInfo = slot.GetTokenInfo();
                }
                catch (Pkcs11Exception ex)
                {
                    if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                        throw;
                }

                if (tokenInfo != null)
                    tokens.Add(new Token(slot, tokenInfo.ManufacturerId, tokenInfo.Model, tokenInfo.SerialNumber, tokenInfo.Label));
            }

            return tokens;
        }

        /// <summary>
        /// Gets private keys and certificates stored in token (smartcard) accessible via PKCS#11 interface
        /// </summary>
        /// <param name="token">PKCS#11 token (smartcard) that should be explored</param>
        /// <param name="login">Flag indicating whether token login with provided PIN should be performed</param>
        /// <param name="pin">PIN for the token (smartcard)</param>
        /// <param name="privateKeys">List of private keys stored in token (smartcard)</param>
        /// <param name="certificates">List of certificates stored in token (smartcard)</param>
        public void GetTokenObjects(Token token, bool login, string pin, out List<PrivateKey> privateKeys, out List<Certificate> certificates)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            if (token == null)
                throw new ArgumentNullException("token");

            // Note: PIN may be null when smartcard reader with pin pad is used

            privateKeys = new List<PrivateKey>();
            certificates = new List<Certificate>();

            using (Session session = token.Slot.OpenSession(true)) //false
            {
                if (login == true)
                    session.Login(CKU.CKU_USER, pin);

                // Define search template for private keys
                List<ObjectAttribute> keySearchTemplate = new List<ObjectAttribute>();
                keySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                keySearchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));

                // Define private key attributes that should be read
                List<CKA> keyAttributes = new List<CKA>();
                keyAttributes.Add(CKA.CKA_ID);
                keyAttributes.Add(CKA.CKA_LABEL);
                keyAttributes.Add(CKA.CKA_KEY_TYPE);

                // Define RSA private key attributes that should be read
                List<CKA> rsaAttributes = new List<CKA>();
                rsaAttributes.Add(CKA.CKA_MODULUS);
                rsaAttributes.Add(CKA.CKA_PUBLIC_EXPONENT);

                #region temp

                //List<ObjectHandle> foundKeyObjects1 = session.FindAllObjects(keySearchTemplate);
                //List<CKA> keyAttributes1 = new List<CKA>();
                //foreach (var value in Enum.GetValues(typeof(CKA)))
                //{
                //    keyAttributes1.Add((CKA) value);
                //}
                //foreach (ObjectHandle foundKeyObject in foundKeyObjects1)
                //{
                //    List<ObjectAttribute> keyObjectAttributes = session.GetAttributeValue(foundKeyObject, keyAttributes1);
                //    Console.WriteLine(keyObjectAttributes.Count);
                //}

                #endregion
                // Find private keys
                List<ObjectHandle> foundKeyObjects = session.FindAllObjects(keySearchTemplate);
                foreach (ObjectHandle foundKeyObject in foundKeyObjects)
                {
                    //session.DestroyObject(foundKeyObject);
                    //continue;
                    List<ObjectAttribute> keyObjectAttributes = session.GetAttributeValue(foundKeyObject, keyAttributes);

                    string ckaId = ConvertUtils.BytesToHexString(keyObjectAttributes[0].GetValueAsByteArray());
                    string ckaLabel = keyObjectAttributes[1].GetValueAsString();
                    AsymmetricKeyParameter publicKey = null;

                    if (keyObjectAttributes[2].GetValueAsUlong() == Convert.ToUInt64(CKK.CKK_RSA))
                    {
                        List<ObjectAttribute> rsaObjectAttributes = session.GetAttributeValue(foundKeyObject, rsaAttributes);

                        var arrayMod = rsaObjectAttributes[0].GetValueAsByteArray();
                        BigInteger modulus = new BigInteger(1, arrayMod);//1
                        BigInteger exponent = new BigInteger(1, rsaObjectAttributes[1].GetValueAsByteArray());
                        publicKey = new RsaKeyParameters(false, modulus, exponent); //false
                    }
                    
                    privateKeys.Add(new PrivateKey(ckaId, ckaLabel, publicKey));
                }

                // Define search template for X.509 certificates
                List<ObjectAttribute> certSearchTemplate = new List<ObjectAttribute>();
                certSearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                certSearchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                certSearchTemplate.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));

                // Define certificate attributes that should be read
                List<CKA> certAttributes = new List<CKA>();
                certAttributes.Add(CKA.CKA_ID);
                certAttributes.Add(CKA.CKA_LABEL);
                certAttributes.Add(CKA.CKA_VALUE);

                // Find X.509 certificates
                List<ObjectHandle> foundCertObjects = session.FindAllObjects(certSearchTemplate);
                foreach (ObjectHandle foundCertObject in foundCertObjects)
                {
                    List<ObjectAttribute> objectAttributes = session.GetAttributeValue(foundCertObject, certAttributes);

                    string ckaId = ConvertUtils.BytesToHexString(objectAttributes[0].GetValueAsByteArray());
                    string ckaLabel = objectAttributes[1].GetValueAsString();
                    byte[] ckaValue = objectAttributes[2].GetValueAsByteArray();

                    certificates.Add(new Certificate(ckaId, ckaLabel, ckaValue));
                }

                if (login == true)
                    session.Logout();
            }
        }

        public void Write()
        {
            //var publicKeyAttributes = new List<ObjectAttribute>();
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, ckaId));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS, publicKeyParams.Modulus));
            //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, publicKeyParams.Exponent));
            //var publicKeyHandle = session.CreateObject(publicKeyAttributes);
        }

        public void Write(string pin, byte[] certificate)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            var slot = GetUsableSlot();
            using (Session session = slot.OpenSession(false))
            {
                session.Login(CKU.CKU_USER, pin);

                var obj = ImportCertificate(session, certificate);

                //// Destroy certificate
                //session.DestroyObject(obj);

                session.Logout();
            }
        }

        public void Clear(string pin)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            var slot = GetUsableSlot();
            using (Session session = slot.OpenSession(false))
            {
                session.Login(CKU.CKU_USER, pin);

                var objects = session.FindAllObjects(new List<ObjectAttribute>());
                foreach (var objectHandle in objects)
                {
                    session.DestroyObject(objectHandle); //delete

                }

                session.Logout();
            }
        }

        public void WritePrivate(string pin, byte[] certificate, string pass)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            var slot = GetUsableSlot();
            using (Session session = slot.OpenSession(false))
            {
                session.Login(CKU.CKU_USER, pin);

                var obj = ImportPrivateCertificate(session, certificate, pass);

                //// Destroy certificate
                //session.DestroyObject(obj);

                session.Logout();
            }
        }

        Slot GetUsableSlot()
        {
            //List<Token> tokens = new List<Token>();

            List<Slot> slots = _pkcs11.GetSlotList(true);
            if (slots.Count == 0)
                return null;
            // First slot with token present is OK...
            Slot matchingSlot = slots[0];

            foreach (Slot slot in slots)
            {
                TokenInfo tokenInfo = null;

                try
                {
                    tokenInfo = slot.GetTokenInfo();
                }
                catch (Pkcs11Exception ex)
                {
                    if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                        throw;
                }

                if (tokenInfo != null)
                {
                    matchingSlot = slot;
                    return matchingSlot;
                    break;
                    //tokens.Add(new Token(slot, tokenInfo.ManufacturerId, tokenInfo.Model, tokenInfo.SerialNumber, tokenInfo.Label));
                }
            }

            return null;
        }

        ObjectHandle ImportCertificate(Session session, byte[] certificate, byte[] encodedCert = null)
        {
            // Parse certificate
            X509CertificateParser x509CertificateParser = new X509CertificateParser();

            X509Certificate x509Certificate = x509CertificateParser.ReadCertificate(certificate);
            // Get public key from certificate
            AsymmetricKeyParameter pubKeyParams = x509Certificate.GetPublicKey();
            if (!(pubKeyParams is RsaKeyParameters))
                throw new NotSupportedException("Currently only RSA keys are supported");
            RsaKeyParameters rsaPubKeyParams = (RsaKeyParameters)pubKeyParams;
            //RSACryptoServiceProvider key = cert.PublicKey.Key as RSACryptoServiceProvider;

            //// Find corresponding private key
            //List<ObjectAttribute> privKeySearchTemplate = new List<ObjectAttribute>();
            //privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            //privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
            //privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_MODULUS, rsaPubKeyParams.Modulus.ToByteArrayUnsigned()));
            //privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, rsaPubKeyParams.Exponent.ToByteArrayUnsigned()));

            //List<ObjectHandle> foundObjects = session.FindAllObjects(privKeySearchTemplate);
            //if (foundObjects.Count != 1)
            //    throw new ObjectNotFoundException("Corresponding RSA private key not found");

            //ObjectHandle privKeyObjectHandle = foundObjects[0];

            //    //Read CKA_LABEL and CKA_ID attributes of private key
            //   List<CKA> privKeyAttrsToRead = new List<CKA>();
            //privKeyAttrsToRead.Add(CKA.CKA_LABEL);
            //    privKeyAttrsToRead.Add(CKA.CKA_ID);

            //    List<ObjectAttribute> privKeyAttributes = session.GetAttributeValue(privKeyObjectHandle, privKeyAttrsToRead);
            var cn = x509Certificate.SubjectDN.ToString();
            //var cn2 = cert.SubjectName.Name;
            byte[] thumbPrint = encodedCert;
            if (thumbPrint == null)
                using (SHA1Managed sha1Managed = new SHA1Managed())
                    thumbPrint = sha1Managed.ComputeHash(x509Certificate.GetEncoded());

            // Define attributes of new certificate object
            List<ObjectAttribute> certificateAttributes = new List<ObjectAttribute>();
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, cn));// privKeyAttributes[0].GetValueAsString()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TRUSTED, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, x509Certificate.SubjectDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ID, thumbPrint));//Encoding.ASCII.GetBytes(cn)));// privKeyAttributes[1].GetValueAsByteArray()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ISSUER, x509Certificate.IssuerDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SERIAL_NUMBER, new DerInteger(x509Certificate.SerialNumber).GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, x509Certificate.GetEncoded()));
            //PrivateKeyInfoFactory.CreatePrivateKeyInfo(new RsaKeyParameters(
            //    ))
            // Create certificate object
            return session.CreateObject(certificateAttributes);
        }

        ObjectHandle ImportPrivateCertificate(Session session, byte[] certBytes, string pass)
        {
            var ss = new SecureString();
            for (var i = 0; i < pass.Length; i++)
            {
                ss.AppendChar(pass[i]);
            }
            X509Certificate2 cert = new X509Certificate2(certBytes, ss, X509KeyStorageFlags.Exportable);
            var crt = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(cert);
            var encodedCert = crt.GetEncoded();
            
            RSAParameters privateKeyParamsNet;
            privateKeyParamsNet = cert.GetRSAPrivateKey().ExportParameters(true);
            //Org.BouncyCastle.Security.DotNetUtilities.ToRSA(privateKeyParamsNet)

            var cn = cert.Subject.ToString();
            //var cn2 = cert.SubjectName.Name;
            byte[] thumbPrint = null;
            using (SHA1Managed sha1Managed = new SHA1Managed())
                thumbPrint = sha1Managed.ComputeHash(cert.RawData);

            var pair = DotNetUtilities.GetRsaKeyPair(privateKeyParamsNet);
            var pair2 = DotNetUtilities.GetRsaPublicKey(privateKeyParamsNet);
            AsymmetricKeyParameter pairPrivate;
            pairPrivate = pair.Private;

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
            var privateKeyAttributes = new List<ObjectAttribute>();
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, thumbPrint));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, cn));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));//true
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));//true
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN_RECOVER, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS, privateKeyParamsNet.Modulus));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, privateKeyParamsNet.Exponent));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE_EXPONENT, privateKeyParamsNet.D));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIME_1, privateKeyParamsNet.P));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIME_2, privateKeyParamsNet.Q));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_EXPONENT_1, privateKeyParamsNet.DP));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_EXPONENT_2, privateKeyParamsNet.DQ));
            //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_COEFFICIENT, privateKeyParamsNet.InverseQ));

            //var privateKeyAttributes = new List<ObjectAttribute>()
            //{
            //    new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            //    new ObjectAttribute(CKA.CKA_TOKEN, true),
            //    new ObjectAttribute(CKA.CKA_PRIVATE, true),
            //    new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            //    new ObjectAttribute(CKA.CKA_LABEL, cn),
            //    new ObjectAttribute(CKA.CKA_ID, thumbPrint),
            //    new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            //    new ObjectAttribute(CKA.CKA_MODULUS, privateKeyParams.Modulus.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, privateKeyParams.PublicExponent.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_PRIVATE_EXPONENT, privateKeyParams.Exponent.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_PRIME_1, privateKeyParams.P.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_PRIME_2, privateKeyParams.Q.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_EXPONENT_1, privateKeyParams.DP.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_EXPONENT_2, privateKeyParams.DQ.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_COEFFICIENT, privateKeyParams.QInv.ToByteArrayUnsigned())
            //};

            // Generate random initialization vector
            byte[] iv = session.GenerateRandom(8);
            // Create temporary DES3 key for wrapping/unwrapping
            var tempKeyAttributes = new List<ObjectAttribute>();
            tempKeyAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
            tempKeyAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_DES3));
            tempKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
            tempKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));
            var tempKey = session.GenerateKey(new Mechanism(CKM.CKM_DES3_KEY_GEN), tempKeyAttributes);

            var result = new MemoryStream();
            session.Encrypt(new Mechanism(CKM.CKM_DES3_CBC_PAD, iv), tempKey, new MemoryStream(unencryptedPrivateKey), result);
            var encryptedPrivateKey = result.ToArray();

            //var privateKeyHandle = session.CreateObject(privateKeyAttributes);

            var privateKeyHandle = session.UnwrapKey(new Mechanism(CKM.CKM_DES3_CBC_PAD, iv), tempKey, encryptedPrivateKey, privateKeyAttributes);



            //session.Encrypt(new Mechanism(CKM.CKM_DES3_CBC_PAD, iv), tempKey, new MemoryStream(unencryptedPrivateKey), result);

            var publicKey = new RsaKeyParameters(true, privateKeyParams.Modulus, privateKeyParams.Exponent); //false

            //Mechanism mechanism = new Mechanism(CKM.CKM_RSA_PKCS); // session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
            //session.UnwrapKey(mechanism, privateKeyHandle, )

            //write x509 certificate
            ImportCertificate(session, encodedCert, thumbPrint);

            return privateKeyHandle;
            //var privateKeyAttributes = new List<ObjectAttribute>()
            //{
            //    new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            //    new ObjectAttribute(CKA.CKA_TOKEN, true),
            //    new ObjectAttribute(CKA.CKA_PRIVATE, true),
            //    new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            //    new ObjectAttribute(CKA.CKA_LABEL, cert.Subject),
            //    new ObjectAttribute(CKA.CKA_ID, thumbPrint),
            //    new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            //    new ObjectAttribute(CKA.CKA_MODULUS, rsaPrivKeyParams.Modulus.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, rsaPrivKeyParams.PublicExponent.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_PRIVATE_EXPONENT, rsaPrivKeyParams.Exponent.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_PRIME_1, rsaPrivKeyParams.P.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_PRIME_2, rsaPrivKeyParams.Q.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_EXPONENT_1, rsaPrivKeyParams.DP.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_EXPONENT_2, rsaPrivKeyParams.DQ.ToByteArrayUnsigned()),
            //    new ObjectAttribute(CKA.CKA_COEFFICIENT, rsaPrivKeyParams.QInv.ToByteArrayUnsigned())
            //};


        }

        public void ConvertPfxToPem(
            string pfxPath,
            string pfxPassword,
            string keyPath)
        {
            using (Stream stream = File.Open(pfxPath, FileMode.Open))
            {
                Pkcs12Store pkcs = new Pkcs12Store(stream, pfxPassword.ToCharArray());

                foreach (string alias in pkcs.Aliases)
                {
                    if (pkcs.IsKeyEntry(alias) && pkcs.GetKey(alias).Key.IsPrivate)
                    {
                        AsymmetricKeyParameter privateKey = pkcs.GetKey(alias).Key;

                        using (Stream s = new FileStream(keyPath, FileMode.Create))
                        using (TextWriter textWriter = new StreamWriter(s))
                        {
                            var generator = new MiscPemGenerator(privateKey);

                            PemWriter pemWriter = new PemWriter(textWriter);
                            pemWriter.WriteObject(generator);
                            textWriter.Flush();
                        }
                    }
                }
            }
        }

        #region IDisposable

        /// <summary>
        /// Disposes object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes object
        /// </summary>
        /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                // Dispose managed objects
                if (disposing)
                {
                    if (_pkcs11 != null)
                    {
                        _pkcs11.Dispose();
                        _pkcs11 = null;
                    }
                }

                // Dispose unmanaged objects

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs11Explorer()
        {
            Dispose(false);
        }

        #endregion
    }
}
