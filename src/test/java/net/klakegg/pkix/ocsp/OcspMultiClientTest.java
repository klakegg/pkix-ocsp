package net.klakegg.pkix.ocsp;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class OcspMultiClientTest {

    @Test
    public void handlingNoCertificates() throws OcspException {
        OcspMultiClient client = OcspMultiClient.builder().build();

        Assert.assertEquals(client.verify(), OcspResult.EMPTY);
        Assert.assertEquals(client.verify(null, new X509Certificate[0]), OcspResult.EMPTY);
    }
}
