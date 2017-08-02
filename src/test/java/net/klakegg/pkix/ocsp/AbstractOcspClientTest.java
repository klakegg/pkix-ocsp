package net.klakegg.pkix.ocsp;

import net.klakegg.pkix.ocsp.api.OcspFetcher;
import net.klakegg.pkix.ocsp.api.OcspFetcherResponse;
import net.klakegg.pkix.ocsp.util.CertificateHelper;
import org.mockito.Mockito;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * @author erlend
 */
public class AbstractOcspClientTest {

    private X509Certificate subject =
            CertificateHelper.parse(getClass().getResourceAsStream("/buypass-test/certificate-valid-01.cer"));

    private X509Certificate issuer =
            CertificateHelper.parse(getClass().getResourceAsStream("/buypass-test/issuer.cer"));

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

    protected OcspFetcher createOcspFetcher(OcspFetcherResponse fetcherResponse) throws IOException {
        OcspFetcher fetcher = Mockito.mock(OcspFetcher.class);
        Mockito.when(fetcher.fetch(Mockito.any(URI.class), Mockito.any(byte[].class))).thenReturn(fetcherResponse);

        return fetcher;
    }
}
