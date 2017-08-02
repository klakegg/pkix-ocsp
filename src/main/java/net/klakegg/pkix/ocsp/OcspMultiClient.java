package net.klakegg.pkix.ocsp;

import net.klakegg.pkix.ocsp.builder.BuildHandler;
import net.klakegg.pkix.ocsp.builder.Builder;
import net.klakegg.pkix.ocsp.builder.Properties;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collections;

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
            public OcspMultiClient perform(Properties properties) {
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
            return new OcspResult(Collections.<BigInteger, OcspResponse>emptyMap());

        X509Certificate issuer = findIntermediate(certificates[0]);

        URI uri = properties.get(OVERRIDE_URL);

        if (uri == null) {
            uri = detectOcspUri(certificates[0]);

            // In case no URI was detected.
            if (uri == null)
                return OcspResult.empty();
        }

        OCSPReq request = generateRequest(issuer, certificates);

        OCSPResp response = fetch(request, uri);

        verifyResponse(response);

        return parseResponseObject(response);
    }
}
