package net.klakegg.pkix.ocsp;

import org.testng.annotations.Test;

/**
 * @author erlend
 */
public class OcspClientTest {

    @Test
    public void simple() {
        OcspClient client = OcspClient.builder()
                .set(OcspClient.EXCEPTION_ON_UNKNOWN, false)
                .set(OcspClient.EXCEPTION_ON_REVOKED, false)
                .build();
    }

}
