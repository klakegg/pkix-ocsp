package net.klakegg.pkix.ocsp.issuer;

import net.klakegg.pkix.ocsp.*;
import net.klakegg.pkix.ocsp.util.CertificateHelper;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class CommfidesTestOcspTest {

    private X509Certificate subjectValid =
            CertificateHelper.parse(getClass().getResourceAsStream("/commfides-test/certificate-valid.cer"));

    private X509Certificate subjectUnknown =
            CertificateHelper.parse(getClass().getResourceAsStream("/commfides-test/certificate-unknown.cer"));

    private X509Certificate issuer =
            CertificateHelper.parse(getClass().getResourceAsStream("/commfides-test/issuer.cer"));

    @Test
    public void simpleUnknown() throws OcspException {
        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.EXCEPTION_ON_REVOKED, false)
                .set(OcspClient.EXCEPTION_ON_UNKNOWN, false)
                .build();

        CertificateResult response = ocspClient.verify(subjectUnknown, issuer);

        Assert.assertEquals(response.getStatus(), CertificateStatus.UNKNOWN);
        Assert.assertNotNull(response.getThisUpdate());
        Assert.assertNull(response.getNextUpdate());
    }

    @SuppressWarnings("Duplicates")
    @Test
    public void simpleValid() throws OcspException {
        OcspClient ocspClient = OcspClient.builder()
                .build();

        CertificateResult response = ocspClient.verify(subjectValid, issuer);

        Assert.assertEquals(response.getStatus(), CertificateStatus.GOOD);
        Assert.assertEquals(response.getIssuer(), CertificateIssuer.generate(issuer));
        Assert.assertEquals(response.getUri(), URI.create("http://ocsp1.test.commfides.com/ocsp"));
        Assert.assertEquals(response.getSerialNumber(), new BigInteger("8931197146463012872"));
        Assert.assertNotNull(response.getThisUpdate());
        Assert.assertNull(response.getNextUpdate());

        System.out.println(response);
    }
}
