package net.klakegg.pkix.ocsp;

import org.testng.annotations.Test;

/**
 * @author erlend
 */
public class OcspDigestCalculatorTest {

    @Test(expectedExceptions = IllegalStateException.class)
    public void triggerUnknownAlgorithm() {
        new OcspDigestCalculator("SHA-0", "1.2.3.4.5.6.7.8.9");
    }
}
