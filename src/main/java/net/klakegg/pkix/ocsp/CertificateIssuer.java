package net.klakegg.pkix.ocsp;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * @author erlend
 */
public class CertificateIssuer implements Serializable {

    private static final long serialVersionUID = -5864866954149163735L;

    private static final String ALGORITHM_IDENTIFIER = "1.3.14.3.2.26";

    private byte[] issuerNameHash;

    private byte[] issuerKeyHash;

    public static CertificateIssuer generate(X509Certificate certificate) throws OcspException {
        try {
            // Digest calculator to be used to create values for the issuer certificate.
            // This is done once in case of multiple requests.
            OcspDigestOutputStream digestCalculator = new OcspDigestOutputStream("SHA-1");

            // Create an instance of the issuer certificate for use with Bouncy Caste/ASN1.
            X509CertificateHolder issuerHolder = new X509CertificateHolder(certificate.getEncoded());

            // Calculate hashes to identify issuer certificate.
            byte[] issuerNameHash =
                    digestCalculator.calculate(issuerHolder.toASN1Structure().getSubject().getEncoded(ASN1Encoding.DER));
            byte[] issuerKeyHash =
                    digestCalculator.calculate(issuerHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());

            return new CertificateIssuer(issuerNameHash, issuerKeyHash);
        } catch (Exception e) {
            throw new OcspException("Exception while preparing issuer data: '%s'", e, e.getMessage());
        }
    }

    public static CertificateIssuer generate(CertificateID certificateID) {
        return new CertificateIssuer(certificateID.getIssuerNameHash(), certificateID.getIssuerKeyHash());
    }

    public CertificateIssuer(byte[] issuerNameHash, byte[] issuerKeyHash) {
        this.issuerNameHash = issuerNameHash;
        this.issuerKeyHash = issuerKeyHash;
    }

    public String getAlgorithmIdentifier() {
        return ALGORITHM_IDENTIFIER;
    }

    public byte[] getIssuerNameHash() {
        return issuerNameHash;
    }

    public byte[] getIssuerKeyHash() {
        return issuerKeyHash;
    }

    @Override
    @SuppressWarnings("SimplifiableIfStatement")
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CertificateIssuer that = (CertificateIssuer) o;

        if (!Arrays.equals(issuerNameHash, that.issuerNameHash)) return false;
        return Arrays.equals(issuerKeyHash, that.issuerKeyHash);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(issuerNameHash);
        result = 31 * result + Arrays.hashCode(issuerKeyHash);
        return result;
    }
}
