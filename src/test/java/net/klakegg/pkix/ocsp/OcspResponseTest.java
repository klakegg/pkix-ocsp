package net.klakegg.pkix.ocsp;

import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * @author erlend
 */
public class OcspResponseTest {

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*malformed.*")
    public void malformed() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x01};

        OcspResponse.parse(new ByteArrayInputStream(response)).verifyResponse();
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*internal error.*")
    public void internalError() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x02};

        OcspResponse.parse(new ByteArrayInputStream(response)).verifyResponse();
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*busy.*")
    public void serverBusy() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x03};

        OcspResponse.parse(new ByteArrayInputStream(response)).verifyResponse();
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*[Ss]igned request.*")
    public void signedRequestExpected() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x05};

        OcspResponse.parse(new ByteArrayInputStream(response)).verifyResponse();
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*not authorized.*")
    public void triggerUnauthorized() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x06};

        OcspResponse.parse(new ByteArrayInputStream(response)).verifyResponse();
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*[Uu]nknown.*")
    public void unknown() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x07};

        OcspResponse.parse(new ByteArrayInputStream(response)).verifyResponse();
    }
}
