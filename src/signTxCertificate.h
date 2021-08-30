#ifndef H_CARDANO_APP_SIGN_TX_CERTIFICATE
#define H_CARDANO_APP_SIGN_TX_CERTIFICATE

#include "bufView.h"

void handleCertificateRegistration(read_view_t* view);
void handleCertificateDeregistration(read_view_t* view);
void handleCertificateDelegation(read_view_t* view);
void handleCertificatePoolRetirement(read_view_t* view);

#endif // H_CARDANO_APP_SIGN_TX_CERTIFICATE

