#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __cplusplus
extern "C" {
#endif

int check_cert_revocation_with_crl(
                                   const unsigned char *cert_der, int cert_len,
                                   const unsigned char *crl_der, int crl_len,
                                   const unsigned char *issuer_der_or_null, int issuer_len
                                   );

const char * _Nullable extractCRLFromCert(const unsigned char *cert_der, int cert_len);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END
