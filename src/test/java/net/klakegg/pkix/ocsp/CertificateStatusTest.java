package net.klakegg.pkix.ocsp;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author erlend
 */
public class CertificateStatusTest {

    @Test
    public void simpleValueOf() {
        Assert.assertEquals(CertificateStatus.valueOf("GOOD"), CertificateStatus.GOOD);
    }
}
