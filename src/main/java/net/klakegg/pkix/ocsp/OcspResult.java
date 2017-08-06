package net.klakegg.pkix.ocsp;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Map;

/**
 * @author erlend
 */
public class OcspResult {

    protected static final OcspResult EMPTY = new OcspResult(Collections.<BigInteger, CertificateResult>emptyMap());

    private final Map<BigInteger, CertificateResult> map;

    protected OcspResult(Map<BigInteger, CertificateResult> map) {
        this.map = Collections.unmodifiableMap(map);
    }

    public CertificateResult get(BigInteger serialNumber) {
        return map.get(serialNumber);
    }

    public CertificateResult get(X509Certificate certificate) {
        return get(certificate.getSerialNumber());
    }
}
