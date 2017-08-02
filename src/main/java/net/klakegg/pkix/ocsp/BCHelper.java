package net.klakegg.pkix.ocsp;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
class BCHelper {

    public static final Provider PROVIDER;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            Security.addProvider(new BouncyCastleProvider());

        PROVIDER = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    public static X509CertificateHolder convertToHolder(X509Certificate certificate)
            throws CertificateEncodingException, IOException {
        return new X509CertificateHolder(certificate.getEncoded());
    }
}
