package net.klakegg.pkix.ocsp.issuer;

import net.klakegg.pkix.ocsp.CertificateStatus;
import net.klakegg.pkix.ocsp.OcspException;
import net.klakegg.pkix.ocsp.OcspMultiClient;
import net.klakegg.pkix.ocsp.OcspResult;
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

        Assert.assertEquals(ocspResult.get(subjectUnknown).getStatus(), CertificateStatus.UNKNOWN);
        Assert.assertEquals(ocspResult.get(subjectValid).getStatus(), CertificateStatus.GOOD);
    }
}
