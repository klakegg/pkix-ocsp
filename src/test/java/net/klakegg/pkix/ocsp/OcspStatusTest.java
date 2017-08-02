package net.klakegg.pkix.ocsp;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author erlend
 */
public class OcspStatusTest {

    @Test
    public void simpleValueOf() {
        Assert.assertEquals(OcspStatus.valueOf("GOOD"), OcspStatus.GOOD);
    }
}
