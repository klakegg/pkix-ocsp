package net.klakegg.pkix.ocsp.issuer;

import net.klakegg.pkix.ocsp.CertificateStatus;
import net.klakegg.pkix.ocsp.OcspClient;
import net.klakegg.pkix.ocsp.OcspException;
import net.klakegg.pkix.ocsp.util.CertificateHelper;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * @author erlend
 */
public class PeppolTestOcspTest {

    private X509Certificate subjectExpired =
            CertificateHelper.parse(getClass().getResourceAsStream("/peppol-ap-test/certificate-expired.cer"));

    private X509Certificate subjectValid =
            CertificateHelper.parse(getClass().getResourceAsStream("/peppol-ap-test/certificate-valid.cer"));

    private X509Certificate issuer =
            CertificateHelper.parse(getClass().getResourceAsStream("/peppol-ap-test/issuer.cer"));

    @Test(enabled = false)
    public void simple() throws OcspException {
        OcspClient ocspClient = OcspClient.builder()
                .build();

        Assert.assertEquals(ocspClient.verify(subjectValid, issuer).getStatus(), CertificateStatus.GOOD);
    }

    @Test(enabled = false)
    public void providedIssuers() throws OcspException {
        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.INTERMEDIATES, Collections.singletonList(issuer))
                .build();

        Assert.assertEquals(ocspClient.verify(subjectValid).getStatus(), CertificateStatus.GOOD);
    }

    @Test(enabled = false)
    public void expiredCertificate() throws OcspException {
        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.EXCEPTION_ON_UNKNOWN, false)
                .set(OcspClient.INTERMEDIATES, Collections.singletonList(issuer))
                .build();

        Assert.assertEquals(ocspClient.verify(subjectExpired).getStatus(), CertificateStatus.UNKNOWN);
    }
}
