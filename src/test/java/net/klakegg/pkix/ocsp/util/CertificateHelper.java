package net.klakegg.pkix.ocsp.util;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class CertificateHelper {

    private static final CertificateFactory certFactory;

    static {
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    public static X509Certificate parse(InputStream inputStream) {
        try {
            return (X509Certificate) certFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

}
