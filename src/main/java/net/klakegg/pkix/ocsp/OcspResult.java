package net.klakegg.pkix.ocsp;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;

/**
 * @author erlend
 */
public class OcspResult {

    private final Map<BigInteger, OcspResponse> map;

    protected static OcspResult empty() {
        return new OcspResult(Collections.<BigInteger, OcspResponse>emptyMap());
    }

    protected OcspResult(Map<BigInteger, OcspResponse> map) {
        this.map = Collections.unmodifiableMap(map);
    }

    public OcspResponse get(BigInteger serialNumber) {
        return map.get(serialNumber);
    }

    public OcspResponse get(X509Certificate certificate) {
        return get(certificate.getSerialNumber());
    }
}
