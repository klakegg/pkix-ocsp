package net.klakegg.pkix.ocsp;

import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.*;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * @author erlend
 */
class OcspResponse {

    private final URI uri;

    private final OCSPResp ocspResp;

    public static OcspResponse parse(URI uri, InputStream inputStream) throws IOException {
        return new OcspResponse(uri, new OCSPResp(IOHelper.toByteArray(inputStream)));
    }

    private OcspResponse(URI uri, OCSPResp ocspResp) {
        this.uri = uri;
        this.ocspResp = ocspResp;
    }

    public void verifyResponse() throws OcspException {
        switch (ocspResp.getStatus()) {
            case OCSPResponseStatus.SUCCESSFUL:
                break;
            case OCSPResponseStatus.MALFORMED_REQUEST:
                throw new OcspServerException("Request was malformed.");
            case OCSPResponseStatus.INTERNAL_ERROR:
                throw new OcspServerException("An internal error occurred in the OCSP Server.");
            case OCSPResponseStatus.TRY_LATER:
                throw new OcspServerException("OCSP server is currently too busy.");
            case OCSPResponseStatus.SIG_REQUIRED:
                throw new OcspServerException("Signed request is required for this OCSP Server.");
            case OCSPResponseStatus.UNAUTHORIZED:
                throw new OcspServerException("Your signature was not authorized by the OCSP Server.");
            default:
                throw new OcspServerException("Unknown OCSPResponse status code '%s'.", ocspResp.getStatus());
        }
    }

    public OcspResult getResult() throws OcspException {
        try {
            Object o = ocspResp.getResponseObject();

            if (o instanceof BasicOCSPResp)
                return parseBasicResponse((BasicOCSPResp) o);

            throw new OcspException("Parsing '%s' not supported.", o);
        } catch (OCSPException e) {
            throw new OcspException(e.getMessage(), e);
        }
    }

    protected OcspResult parseBasicResponse(BasicOCSPResp response) {
        // TODO Verify signature

        Map<BigInteger, CertificateResult> map = new HashMap<>();

        for (SingleResp singleResponse : response.getResponses()) {
            map.put(singleResponse.getCertID().getSerialNumber(),
                    new CertificateResult(
                            parseCertificateStatus(singleResponse.getCertStatus()),
                            CertificateIssuer.generate(singleResponse.getCertID()),
                            uri,
                            singleResponse.getCertID().getSerialNumber(),
                            singleResponse.getThisUpdate(),
                            singleResponse.getNextUpdate()
                    )
            );
        }

        return new OcspResult(map);
    }

    protected CertificateStatus parseCertificateStatus(org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus) {
        if (certificateStatus == null)
            return CertificateStatus.GOOD;
        else if (certificateStatus instanceof RevokedStatus)
            return CertificateStatus.REVOKED;
        else // if (certificateStatus instanceof UnknownStatus)
            return CertificateStatus.UNKNOWN;
    }
}
