package net.klakegg.pkix.ocsp;

import net.klakegg.pkix.ocsp.util.CertificateHelper;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * @author erlend
 */
public class CommfidesTestMultiOcspTest {

    private X509Certificate subjectUnknown =
            CertificateHelper.parse(getClass().getResourceAsStream("/commfides-test/certificate-unknown.cer"));

    private X509Certificate subjectValid =
            CertificateHelper.parse(getClass().getResourceAsStream("/commfides-test/certificate-valid.cer"));

    private X509Certificate issuer =
            CertificateHelper.parse(getClass().getResourceAsStream("/commfides-test/issuer.cer"));

    @Test
    public void simple() throws OcspException {
        OcspMultiClient ocspMultiClient = OcspMultiClient.builder()
                .set(OcspMultiClient.INTERMEDIATES, Collections.singletonList(issuer))
                .build();

        OcspResult ocspResult = ocspMultiClient.verify(
                subjectUnknown, subjectValid
        );

        Assert.assertEquals(ocspResult.get(subjectUnknown).getStatus(), OcspStatus.UNKNOWN);
        Assert.assertEquals(ocspResult.get(subjectValid).getStatus(), OcspStatus.GOOD);
    }
}
