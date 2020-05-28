// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.Identity.Web
{
    /// <summary>
    /// Certificate Loader.
    /// </summary>
    public class DefaultCertificateLoader : ICertificateLoader
    {
        /// <summary>
        /// Load the certificate from the description if needed.
        /// </summary>
        /// <param name="certificateDescription">Description of the certificate.</param>
        public void LoadIfNeeded(CertificateDescription certificateDescription)
        {
            if (certificateDescription.Certificate == null)
            {
                switch (certificateDescription.SourceType)
                {
                    case CertificateSource.KeyVault:
                        certificateDescription.Certificate = LoadFromKeyVault(certificateDescription.Container, certificateDescription.ReferenceOrValue);
                        break;
                    case CertificateSource.Base64Encoded:
                        certificateDescription.Certificate = LoadFromBase64Encoded(certificateDescription.ReferenceOrValue);
                        break;
                    case CertificateSource.Path:
                        // TODO
                        break;
                    case CertificateSource.StoreWithThumbprint:
                        certificateDescription.Certificate = LoadLocalCertificateFromThumbprint(certificateDescription.ReferenceOrValue);
                        break;
                    case CertificateSource.StoreWithDistinguishedName:
                        certificateDescription.Certificate = LoadFromStoreWithDistinguishedName(certificateDescription.Container, certificateDescription.ReferenceOrValue);
                        break;
                    default:
                        break;
                }
            }
        }

        private static X509Certificate2 LoadFromBase64Encoded(string certificateBase64)
        {
            byte[] decoded = Convert.FromBase64String(certificateBase64);
            X509Certificate2 cert = new X509Certificate2(decoded);
            return cert;
        }

        private static X509Certificate2 LoadFromKeyVault(string keyVaultUrl, string certificateName)
        {
            throw new NotImplementedException();
        }

        private static X509Certificate2 LoadLocalCertificateFromThumbprint(
            string certificateThumbprint,
            StoreLocation certificateStoreLocation = StoreLocation.CurrentUser,
            StoreName certificateStoreName = StoreName.My)
        {
            X509Store x509Store = new X509Store(
                certificateStoreName,
                certificateStoreLocation);

            X509Certificate2 cert = FindCertificateByCriterium(
                x509Store,
                X509FindType.FindByThumbprint,
                certificateThumbprint);
            return cert;
        }

        private static X509Certificate2 LoadFromStoreWithDistinguishedName(string store, string certificateSubjectDistinguishedName)
        {
            string[] path = store.Split('/');
            if (path.Length == 2)
            {

            }

            StoreLocation certificateStoreLocation = StoreLocation.CurrentUser;
            StoreName certificateStoreName = StoreName.My;
            X509Store x509Store = new X509Store(certificateStoreName, certificateStoreLocation);
            var by = X509FindType.FindBySubjectDistinguishedName;
            X509Certificate2 cert = FindCertificateByCriterium(x509Store, X509FindType.FindBySubjectDistinguishedName, certificateSubjectDistinguishedName);
            return cert;
        }

        /// <summary>
        /// Find a certificate by criteria
        /// </summary>
        /// <param name="x509Store"></param>
        /// <param name="identifierCriterium"></param>
        /// <param name="certificateIdentifier"></param>
        /// <returns></returns>
        private static X509Certificate2 FindCertificateByCriterium(
            X509Store x509Store,
            X509FindType identifierCriterium,
            string certificateIdentifier)
        {
            x509Store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certCollection = x509Store.Certificates;

            // Find unexpired certificates.
            X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

            // From the collection of unexpired certificates, find the ones with the correct name.
            X509Certificate2Collection signingCert = currentCerts.Find(identifierCriterium, certificateIdentifier, false);

            // Return the first certificate in the collection, has the right name and is current.
            var cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();
            return cert;
        }
    }
}
