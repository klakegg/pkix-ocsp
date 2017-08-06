package net.klakegg.pkix.ocsp;

import net.klakegg.pkix.ocsp.util.CertificateHelper;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class CertificateIssuerTest {

    private X509Certificate issuerBuypass =
            CertificateHelper.parse(getClass().getResourceAsStream("/buypass-test/issuer.cer"));

    private X509Certificate issuerCommfides =
            CertificateHelper.parse(getClass().getResourceAsStream("/commfides-test/issuer.cer"));

    @SuppressWarnings({"ObjectEqualsNull", "EqualsWithItself"})
    @Test
    public void simpleEquals() throws OcspException {
        CertificateIssuer buypassIssuer = CertificateIssuer.generate(issuerBuypass);
        CertificateIssuer commfidesIssuer = CertificateIssuer.generate(issuerCommfides);

        Assert.assertTrue(buypassIssuer.equals(CertificateIssuer.generate(issuerBuypass)));
        Assert.assertTrue(commfidesIssuer.equals(CertificateIssuer.generate(issuerCommfides)));

        Assert.assertFalse(buypassIssuer.equals(commfidesIssuer));
        Assert.assertFalse(commfidesIssuer.equals(buypassIssuer));

        Assert.assertFalse(buypassIssuer.equals(null));
        Assert.assertFalse(buypassIssuer.equals(new Object()));
        Assert.assertTrue(buypassIssuer.equals(buypassIssuer));
    }

    @Test
    public void simpleHashCode() throws OcspException {
        Assert.assertNotNull(CertificateIssuer.generate(issuerBuypass).hashCode());
    }

    @Test(expectedExceptions = OcspException.class)
    public void triggerExceptionInGenerate() throws OcspException {
        CertificateIssuer.generate((X509Certificate) null);
    }
}
