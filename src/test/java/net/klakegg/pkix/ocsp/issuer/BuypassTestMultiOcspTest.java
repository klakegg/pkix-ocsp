package net.klakegg.pkix.ocsp.issuer;

import net.klakegg.pkix.ocsp.CertificateStatus;
import net.klakegg.pkix.ocsp.OcspException;
import net.klakegg.pkix.ocsp.OcspMultiClient;
import net.klakegg.pkix.ocsp.OcspResult;
import net.klakegg.pkix.ocsp.fetcher.ApacheOcspFetcher;
import net.klakegg.pkix.ocsp.util.CertificateHelper;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;
import java.util.Collections;

/**
 * @author erlend
 */
public class BuypassTestMultiOcspTest {

    private X509Certificate subjectValid01 =
            CertificateHelper.parse(getClass().getResourceAsStream("/buypass-test/certificate-valid-01.cer"));

    private X509Certificate subjectValid02 =
            CertificateHelper.parse(getClass().getResourceAsStream("/buypass-test/certificate-valid-02.cer"));

    private X509Certificate issuer =
            CertificateHelper.parse(getClass().getResourceAsStream("/buypass-test/issuer.cer"));

    @Test
    public void simple() throws OcspException {
        OcspMultiClient ocspMultiClient = OcspMultiClient.builder()
                .set(OcspMultiClient.INTERMEDIATES, Collections.singletonList(issuer))
                .set(OcspMultiClient.FETCHER, ApacheOcspFetcher.builder().build())
                .build();

        OcspResult ocspResult = ocspMultiClient.verify(
                subjectValid01, subjectValid02
        );

        Assert.assertEquals(ocspResult.get(subjectValid01).getStatus(), CertificateStatus.GOOD);
        Assert.assertEquals(ocspResult.get(subjectValid02).getStatus(), CertificateStatus.GOOD);
    }
}
