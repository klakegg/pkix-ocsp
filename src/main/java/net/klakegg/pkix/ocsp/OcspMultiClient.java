package net.klakegg.pkix.ocsp;

import net.klakegg.pkix.ocsp.builder.BuildHandler;
import net.klakegg.pkix.ocsp.builder.Builder;
import net.klakegg.pkix.ocsp.builder.Properties;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;

/**
 * Implementation of OCSP client supporting verification of multiple certificates at once using multiple requests in
 * the OCSP request. This implementation requires intermediates to be set using the builder.
 *
 * @author erlend
 */
public class OcspMultiClient extends AbstractOcspClient {

    /**
     * Builder to create an instance of the client.
     *
     * @return Prepared client.
     */
    public static Builder<OcspMultiClient> builder() {
        return new Builder<>(new BuildHandler<OcspMultiClient>() {
            @Override
            public OcspMultiClient build(Properties properties) {
                return new OcspMultiClient(properties);
            }
        });
    }

    /**
     * {@inheritDoc}
     */
    private OcspMultiClient(Properties properties) {
        super(properties);
    }

    public OcspResult verify(X509Certificate... certificates) throws OcspException {
        if (certificates.length == 0)
            return OcspResult.EMPTY;

        X509Certificate issuer = findIntermediate(certificates[0]);

        return verify(CertificateIssuer.generate(issuer), certificates);
    }

    public OcspResult verify(CertificateIssuer issuer, X509Certificate... certificates) throws OcspException {
        if (certificates.length == 0)
            return OcspResult.EMPTY;

        URI uri = properties.get(OVERRIDE_URL);

        if (uri == null) {
            uri = detectOcspUri(certificates[0]);

            // In case no URI was detected.
            if (uri == null)
                return OcspResult.EMPTY;
        }

        BigInteger[] serialNumbers = new BigInteger[certificates.length];
        for (int i = 0; i < certificates.length; i++)
            serialNumbers[i] = certificates[i].getSerialNumber();

        return verify(uri, issuer, serialNumbers);
    }

    public OcspResult verify(URI uri, CertificateIssuer issuer, BigInteger... serialNumbers) throws OcspException {
        OcspRequest request = new OcspRequest();
        request.setIssuer(issuer);
        request.addCertificates(serialNumbers);
        if (properties.get(NONCE))
            request.addNonce();

        OcspResponse response = fetch(request, uri);
        response.verifyResponse();

        return response.getResult();
    }
}
