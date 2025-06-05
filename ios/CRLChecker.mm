#import "CRLChecker.h"
#import <openssl/x509.h>
#import <openssl/x509v3.h>
#import <string.h>
#import <stdlib.h>

/**
 * Verifies whether a given X.509 certificate has been revoked, using a CRL (Certificate Revocation List)
 * and a trusted issuer certificate. This function performs:
 *   1. Certificate and CRL parsing
 *   2. CRL signature validation using the issuer's public key
 *   3. CRL issuer identity check
 *   4. CRL validity period check (notBefore and notAfter)
 *   5. Serial number match in the CRL entries
 *
 * @param cert_der Pointer to the DER-encoded certificate being checked.
 * @param cert_len Length of the certificate in bytes.
 * @param crl_der Pointer to the DER-encoded CRL.
 * @param crl_len Length of the CRL in bytes.
 * @param issuer_der_or_null Pointer to the DER-encoded issuer certificate (should have signed the CRL).
 * @param issuer_len Length of the issuer certificate in bytes.
 *
 * @return int Status code:
 *   1  = The certificate is revoked.
 *   0  = The certificate is not revoked.
 *  -1  = Certificate failed to parse.
 *  -2  = CRL failed to parse.
 *  -3  = CRL signature verification failed.
 *  -4  = CRL is not valid at current time (outside its notBefore/notAfter).
 *  -5  = CRL issuer does not match provided issuer certificate.
 */
int check_cert_revocation_with_crl(
                                   const unsigned char *cert_der, int cert_len,
                                   const unsigned char *crl_der, int crl_len,
                                   const unsigned char *issuer_der_or_null, int issuer_len
                                   ) {
  const unsigned char *ptr = cert_der;
  X509 *cert = d2i_X509(NULL, &ptr, cert_len);
  if (!cert) return -1;
  
  ptr = crl_der;
  X509_CRL *crl = d2i_X509_CRL(NULL, &ptr, crl_len);
  if (!crl) {
    X509_free(cert);
    return -2;
  }
  
  // --- Validate CRL signature if issuer is provided ---
  if (issuer_der_or_null != nullptr && issuer_len > 0) {
    const unsigned char *issuerPtr = issuer_der_or_null;
    X509 *issuer = d2i_X509(NULL, &issuerPtr, issuer_len);
    if (!issuer) {
      X509_free(cert);
      X509_CRL_free(crl);
      return -3; // Signature validation failed (issuer unreadable)
    }
    
    EVP_PKEY *pubkey = X509_get_pubkey(issuer);
    if (!pubkey || X509_CRL_verify(crl, pubkey) <= 0) {
      EVP_PKEY_free(pubkey);
      X509_free(issuer);
      X509_free(cert);
      X509_CRL_free(crl);
      return -3; // CRL signature invalid
    }
    
    EVP_PKEY_free(pubkey);
    X509_free(issuer);
  }
  
  // --- Check CRL validity period ---
  const ASN1_TIME *lastUpdate = X509_CRL_get0_lastUpdate(crl);
  const ASN1_TIME *nextUpdate = X509_CRL_get0_nextUpdate(crl);
  if (!lastUpdate || !nextUpdate) {
    X509_free(cert);
    X509_CRL_free(crl);
    return -4;
  }
  
  if (X509_cmp_current_time(lastUpdate) > 0 || X509_cmp_current_time(nextUpdate) < 0) {
    X509_free(cert);
    X509_CRL_free(crl);
    return -4; // CRL is not currently valid
  }
  
  // --- Check CRL issuer matches cert issuer ---
  if (issuer_der_or_null != nullptr && issuer_len > 0) {
    const X509_NAME *crlIssuer = X509_CRL_get_issuer(crl);
    const X509_NAME *certIssuer = X509_get_issuer_name(cert);
    if (X509_NAME_cmp(crlIssuer, certIssuer) != 0) {
      X509_free(cert);
      X509_CRL_free(crl);
      return -5; // CRL issuer mismatch
    }
  }
  
  // --- Check if the certificate is listed in the CRL ---
  ASN1_INTEGER *serial = X509_get_serialNumber(cert);
  STACK_OF(X509_REVOKED) *revoked = X509_CRL_get_REVOKED(crl);
  
  BOOL isRevoked = NO;
  for (int i = 0; i < sk_X509_REVOKED_num(revoked); i++) {
    X509_REVOKED *rev = sk_X509_REVOKED_value(revoked, i);
    if (ASN1_INTEGER_cmp(serial, X509_REVOKED_get0_serialNumber(rev)) == 0) {
      isRevoked = YES;
      break;
    }
  }
  
  X509_free(cert);
  X509_CRL_free(crl);
  return isRevoked ? 1 : 0;
}


/**
 * Extracts the first available CRL Distribution Point URI from a DER-encoded X.509 certificate.
 * This URI is where the CRL (Certificate Revocation List) can be downloaded from.
 *
 * @param cert_der Pointer to the DER-encoded certificate.
 * @param cert_len Length of the certificate in bytes.
 *
 * @return const char* A malloc'd null-terminated string containing the CRL Distribution Point URL,
 *                     or NULL if none is found. The caller is responsible for freeing the memory.
 */
const char *extractCRLFromCert(const unsigned char *cert_der, int cert_len) {
  const unsigned char *ptr = cert_der;
  X509 *cert = d2i_X509(NULL, &ptr, cert_len);
  if (!cert) return NULL;
  
  STACK_OF(DIST_POINT) *crl_dp = static_cast<STACK_OF(DIST_POINT) *>(
                                                                     X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL)
                                                                     );
  
  if (!crl_dp || sk_DIST_POINT_num(crl_dp) == 0) {
    X509_free(cert);
    return NULL;
  }
  
  for (int i = 0; i < sk_DIST_POINT_num(crl_dp); i++) {
    DIST_POINT *dp = sk_DIST_POINT_value(crl_dp, i);
    if (dp->distpoint && dp->distpoint->type == 0) {
      GENERAL_NAMES *names = dp->distpoint->name.fullname;
      for (int j = 0; j < sk_GENERAL_NAME_num(names); j++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(names, j);
        if (gen->type == GEN_URI) {
          ASN1_IA5STRING *uri = gen->d.uniformResourceIdentifier;
          char *url = (char *)malloc(uri->length + 1);
          memcpy(url, uri->data, uri->length);
          url[uri->length] = '\0';
          X509_free(cert);
          sk_DIST_POINT_pop_free(crl_dp, DIST_POINT_free);
          return url;
        }
      }
    }
  }
  
  sk_DIST_POINT_pop_free(crl_dp, DIST_POINT_free);
  X509_free(cert);
  return NULL;
}
