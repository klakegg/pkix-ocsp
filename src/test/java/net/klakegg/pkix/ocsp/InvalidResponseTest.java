package net.klakegg.pkix.ocsp;

import net.klakegg.pkix.ocsp.api.OcspFetcher;
import net.klakegg.pkix.ocsp.api.OcspFetcherResponse;
import net.klakegg.pkix.ocsp.util.CertificateHelper;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class InvalidResponseTest {

    private X509Certificate subject =
            CertificateHelper.parse(getClass().getResourceAsStream("/buypass-test/certificate-valid-01.cer"));

    private X509Certificate issuer =
            CertificateHelper.parse(getClass().getResourceAsStream("/buypass-test/issuer.cer"));

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*malformed.*")
    public void malformed() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x01};

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(createFetcherResponse(response)))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*internal error.*")
    public void internalError() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x02};

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(createFetcherResponse(response)))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*busy.*")
    public void serverBusy() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x03};

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(createFetcherResponse(response)))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*[Ss]igned request.*")
    public void signedRequestExpected() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x05};

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(createFetcherResponse(response)))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*not authorized.*")
    public void triggerUnauthorized() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x06};

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(createFetcherResponse(response)))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*[Uu]nknown.*")
    public void unknown() throws OcspException, IOException {
        byte[] response = new byte[]{0x30, 0x03, 0x0a, 0x01, 0x07};

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(createFetcherResponse(response)))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*404.*")
    public void httpResponse404() throws OcspException, IOException {
        OcspFetcherResponse fetcherResponse = Mockito.mock(OcspFetcherResponse.class);
        Mockito.when(fetcherResponse.getStatus()).thenReturn(404);

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(fetcherResponse))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = ".*text/html.*")
    public void invalidContentType() throws OcspException, IOException {
        OcspFetcherResponse fetcherResponse = Mockito.mock(OcspFetcherResponse.class);
        Mockito.when(fetcherResponse.getStatus()).thenReturn(200);
        Mockito.when(fetcherResponse.getContentType()).thenReturn("text/html");

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(fetcherResponse))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = "Whatever")
    public void fetchIOExceptionRandom() throws OcspException, IOException {
        OcspFetcherResponse fetcherResponse = Mockito.mock(OcspFetcherResponse.class);
        Mockito.when(fetcherResponse.getStatus()).thenThrow(new IOException("Whatever"));

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(fetcherResponse))
                .build();

        ocspClient.verify(subject, issuer);
    }

    @Test(expectedExceptions = OcspException.class, expectedExceptionsMessageRegExp = "Whatever")
    public void fetchIOExceptionInputStream() throws OcspException, IOException {
        OcspFetcherResponse fetcherResponse = Mockito.mock(OcspFetcherResponse.class);
        Mockito.when(fetcherResponse.getStatus()).thenReturn(200);
        Mockito.when(fetcherResponse.getContentType()).thenReturn("application/ocsp-response");
        Mockito.when(fetcherResponse.getContent()).thenThrow(new IOException("Whatever"));

        OcspClient ocspClient = OcspClient.builder()
                .set(OcspClient.FETCHER, createOcspFetcher(fetcherResponse))
                .build();

        ocspClient.verify(subject, issuer);
    }

    protected OcspFetcherResponse createFetcherResponse(byte[] bytes) throws IOException {
        OcspFetcherResponse fetcherResponse = Mockito.mock(OcspFetcherResponse.class);
        Mockito.when(fetcherResponse.getStatus()).thenReturn(200);
        Mockito.when(fetcherResponse.getContentType()).thenReturn("application/ocsp-response");
        Mockito.when(fetcherResponse.getContent()).thenReturn(new ByteArrayInputStream(bytes));

        return fetcherResponse;
    }

    protected OcspFetcher createOcspFetcher(OcspFetcherResponse fetcherResponse) throws IOException {
        OcspFetcher fetcher = Mockito.mock(OcspFetcher.class);
        Mockito.when(fetcher.fetch(Mockito.any(URI.class), Mockito.any(byte[].class))).thenReturn(fetcherResponse);

        return fetcher;
    }
}
