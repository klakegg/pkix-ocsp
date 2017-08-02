package net.klakegg.pkix.ocsp;

import net.klakegg.pkix.ocsp.util.CertificateHelper;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * @author erlend
 */
public class PeppolTestMultiOcspTest {

    private X509Certificate subjectExpired =
            CertificateHelper.parse(getClass().getResourceAsStream("/peppol-ap-test/certificate-expired.cer"));

    private X509Certificate subjectValid =
            CertificateHelper.parse(getClass().getResourceAsStream("/peppol-ap-test/certificate-valid.cer"));

    private X509Certificate issuer =
            CertificateHelper.parse(getClass().getResourceAsStream("/peppol-ap-test/issuer.cer"));

    @Test
    public void simple() throws OcspException {
        OcspMultiClient ocspMultiClient = OcspMultiClient.builder()
                .set(OcspMultiClient.INTERMEDIATES, Collections.singletonList(issuer))
                .build();

        OcspResult ocspResult = ocspMultiClient.verify(
                subjectValid, subjectExpired
        );

        Assert.assertEquals(ocspResult.get(subjectValid).getStatus(), OcspStatus.GOOD);
        Assert.assertNull(ocspResult.get(subjectExpired)); // Multi not supported.
    }
}
