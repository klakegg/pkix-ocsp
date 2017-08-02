package net.klakegg.pkix.ocsp;

import org.testng.annotations.Test;

/**
 * @author erlend
 */
public class OcspDigestOutputStreamTest {

    @Test(expectedExceptions = IllegalStateException.class)
    public void triggerUnknownAlgorithm() {
        new OcspDigestOutputStream("SHA-0", "1.2.3.4.5.6.7.8.9");
    }
}
