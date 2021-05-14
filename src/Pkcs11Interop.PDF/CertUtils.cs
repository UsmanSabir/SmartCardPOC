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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509.Store;
using BCCollections = Org.BouncyCastle.Utilities.Collections;
using BCX509 = Org.BouncyCastle.X509;

namespace Net.Pkcs11Interop.Cert
{
    /// <summary>
    /// Utility class that helps with certificate processing
    /// </summary>
    public static class CertUtils
    {
        /// <summary>
        /// BouncyCastle certificate parser
        /// </summary>
        private static BCX509.X509CertificateParser _x509CertificateParser = new BCX509.X509CertificateParser();

        /// <summary>
        /// Converts raw certificate data to the instance of .NET X509Certificate2 class
        /// </summary>
        /// <param name="data">Raw certificate data</param>
        /// <returns>Instance of .NET X509Certificate2 class</returns>
        public static X509Certificate2 ToDotNetObject(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            return new X509Certificate2(data);
        }

        /// <summary>
        /// Converts the instance of BouncyCastle X509Certificate class to the instance of .NET X509Certificate2 class
        /// </summary>
        /// <param name="cert">Instance of BouncyCastle X509Certificate class</param>
        /// <returns>Instance of .NET X509Certificate2 class</returns>
        public static X509Certificate2 ToDotNetObject(BCX509.X509Certificate cert)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            return new X509Certificate2(ToDerEncodedByteArray(cert));
        }

        /// <summary>
        /// Converts raw certificate data to the instance of BouncyCastle X509Certificate class
        /// </summary>
        /// <param name="data">Raw certificate data</param>
        /// <returns>Instance of BouncyCastle X509Certificate class</returns>
        public static BCX509.X509Certificate ToBouncyCastleObject(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            BCX509.X509Certificate bcCert = _x509CertificateParser.ReadCertificate(data);
            if (bcCert == null)
                throw new CryptographicException("Cannot find the requested object.");

            return bcCert;
        }

        /// <summary>
        /// Converts the instance of .NET X509Certificate2 class to the instance of BouncyCastle X509Certificate class
        /// </summary>
        /// <param name="cert">Instance of .NET X509Certificate2 class</param>
        /// <returns>Instance of BouncyCastle X509Certificate class</returns>
        public static BCX509.X509Certificate ToBouncyCastleObject(X509Certificate2 cert)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            BCX509.X509Certificate bcCert = _x509CertificateParser.ReadCertificate(cert.RawData);
            if (bcCert == null)
                throw new CryptographicException("Cannot find the requested object.");

            return bcCert;
        }

        /// <summary>
        /// Converts the instance of BouncyCastle X509Certificate class to the DER encoded byte array
        /// </summary>
        /// <param name="cert">Instance of BouncyCastle X509Certificate class</param>
        /// <returns>DER encoded byte array</returns>
        public static byte[] ToDerEncodedByteArray(BCX509.X509Certificate cert)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            return cert.GetEncoded();
        }

        /// <summary>
        /// Converts the instance of .NET X509Certificate2 class to the DER encoded byte array
        /// </summary>
        /// <param name="cert">Instance of .NET X509Certificate2 class</param>
        /// <returns>DER encoded byte array</returns>
        public static byte[] ToDerEncodedByteArray(X509Certificate2 cert)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            return cert.RawData;
        }

        /// <summary>
        /// Checks whether certificate is self-signed
        /// </summary>
        /// <param name="certificate">Certificate to be checked</param>
        /// <returns>True if certificate is self-signed; false otherwise</returns>
        public static bool IsSelfSigned(BCX509.X509Certificate certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            try
            {
                certificate.Verify(certificate.GetPublicKey());
                return true;
            }
            catch (Org.BouncyCastle.Security.InvalidKeyException)
            {
                return false;
            }
        }

        /// <summary>
        /// Builds certification path for provided signing certificate
        /// </summary>
        /// <param name="signingCertificate">Signing certificate</param>
        /// <param name="otherCertificates">Other certificates that should be used in path building process. Self-signed certificates from this list are used as trust anchors.</param>
        /// <returns>Certification path for provided signing certificate</returns>
        public static ICollection<BCX509.X509Certificate> BuildCertPath(byte[] signingCertificate, List<byte[]> otherCertificates)
        {
            if (signingCertificate == null)
                throw new ArgumentNullException("signingCertificate");

            List<BCX509.X509Certificate> result = new List<BCX509.X509Certificate>();

            BCX509.X509Certificate signingCert = ToBouncyCastleObject(signingCertificate);
            BCCollections.ISet trustAnchors = new BCCollections.HashSet();
            List<BCX509.X509Certificate> otherCerts = new List<BCX509.X509Certificate>();

            if (IsSelfSigned(signingCert))
            {
                result.Add(signingCert);
            }
            else
            {
                otherCerts.Add(signingCert);

                if (otherCertificates != null)
                {
                    foreach (byte[] otherCertificate in otherCertificates)
                    {
                        BCX509.X509Certificate otherCert = ToBouncyCastleObject(otherCertificate);
                        otherCerts.Add(ToBouncyCastleObject(otherCertificate));
                        if (IsSelfSigned(otherCert))
                            trustAnchors.Add(new TrustAnchor(otherCert, null));
                    }
                }

                if (trustAnchors.Count < 1)
                    throw new PkixCertPathBuilderException("Provided certificates do not contain self-signed root certificate");

                X509CertStoreSelector targetConstraints = new X509CertStoreSelector();
                targetConstraints.Certificate = signingCert;

                PkixBuilderParameters certPathBuilderParameters = new PkixBuilderParameters(trustAnchors, targetConstraints);
                certPathBuilderParameters.AddStore(X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(otherCerts)));
                certPathBuilderParameters.IsRevocationEnabled = false;

                PkixCertPathBuilder certPathBuilder = new PkixCertPathBuilder();
                PkixCertPathBuilderResult certPathBuilderResult = certPathBuilder.Build(certPathBuilderParameters);

                foreach (BCX509.X509Certificate certPathCert in certPathBuilderResult.CertPath.Certificates)
                    result.Add(certPathCert);

                result.Add(certPathBuilderResult.TrustAnchor.TrustedCert);
            }

            return result;
        }


        public static List<byte[]> GetCertificates()
        {
            List<byte[]> result = new List<byte[]>();
            try
            {
                // Parse command line arguments
                string pkcs11Library = null;
                int listTokens = 0;
                int listObjects = 0;
                int sign = 0;
                string tokenSerial = null;
                string tokenLabel = null;
                string pin = null;
                string keyLabel = null;
                string keyId = null;
                string inputPdf = null;
                string outputPdf = null;
                string hashAlg = null;
                string certsDir = null;

                //if (args.Length == 0)
                //    ExitWithHelp(null);

                int i = 0;

                #region List tokens

                pkcs11Library = "acos5evopkcs11.dll";
                listTokens = 1;

                #endregion
                #region List objects

                //pkcs11Library = "acos5evopkcs11.dll";
                listObjects = 1;
                pin = "12345678";
                //tokenSerial = "902000A1C4650A00";
                #endregion


                // Perform requested operation
                using (Pkcs11Explorer pkcs11Explorer = new Pkcs11Explorer(pkcs11Library))
                {
                    Console.WriteLine(string.Format("Listing objects available on token with serial \"{0}\" and label \"{1}\"", tokenSerial, tokenLabel));

                    // Find requested token
                    Token foundToken = null;

                    List<Token> tokens = pkcs11Explorer.GetTokens();
                    foreach (Token token in tokens)
                    {
                        if (!string.IsNullOrEmpty(tokenLabel))
                            if (0 != String.Compare(tokenLabel, token.Label, StringComparison.InvariantCultureIgnoreCase))
                                continue;

                        if (!string.IsNullOrEmpty(tokenSerial))
                            if (0 != String.Compare(tokenSerial, token.SerialNumber, StringComparison.InvariantCultureIgnoreCase))
                                continue;

                        foundToken = token;
                        break;
                    }

                    if (foundToken == null)
                        throw new TokenNotFoundException(string.Format("Token with serial \"{0}\" and label \"{1}\" was not found", tokenSerial, tokenLabel));

                    // Get private keys and certificates stored in requested token
                    List<PrivateKey> privateKeys = null;
                    List<Certificate> certificates = null;
                    pkcs11Explorer.GetTokenObjects(foundToken, true, pin, out privateKeys, out certificates);


                    // Print certificates
                    int k = 1;
                    foreach (Certificate certificate in certificates)
                    {
                        result.Add(certificate.Data);
                        // // X509Certificate2 x509Cert = CertUtils.ToDotNetObject(certificate.Data);

                        k++;
                    }
                }
            }
            catch (Exception ex)
            {

            }

            return result;
        }

    }
}
