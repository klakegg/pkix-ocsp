package net.klakegg.pkix.ocsp;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * @author erlend
 */
class OcspRequest {

    private List<Extension> extensions = new ArrayList<>();

    private X509Certificate[] certificates;

    private ASN1OctetString issuerNameHash;

    private ASN1OctetString issuerKeyHash;

    private AlgorithmIdentifier algorithmIdentifier;

    public void setIssuer(X509Certificate certificate, String digestAlgorithm, String digestOid) throws OcspException {
        try {
            // Digest calculator to be used to create values for the issuer certificate.
            // This is done once in case of multiple requests.
            OcspDigestOutputStream digestCalculator = new OcspDigestOutputStream(digestAlgorithm, digestOid);

            // Set AlgorithmIdentifier
            algorithmIdentifier = digestCalculator.getAlgorithmIdentifier();

            // Create an instance of the issuer certificate for use with Bouncy Caste/ASN1.
           X509CertificateHolder issuerHolder = BCHelper.convertToHolder(certificate);

            // Calculate hashes to identify issuer certificate.
            issuerNameHash = new DEROctetString(
                    digestCalculator.calculate(issuerHolder.toASN1Structure().getSubject().getEncoded(ASN1Encoding.DER)));
            issuerKeyHash = new DEROctetString(
                    digestCalculator.calculate(issuerHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));
        } catch (IOException | CertificateEncodingException e) {
            throw new OcspException("Exception while preparing issuer data: '%s'", e, e.getMessage());
        }
    }

    public void addNonce() {
        byte[] nonce = new byte[16];
        ThreadLocalRandom.current().nextBytes(nonce);
        addExtension(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce)));
    }

    public void addExtension(Extension extension) {
        this.extensions.add(extension);
    }

    public void setCertificates(X509Certificate... certificates) {
        this.certificates = certificates;
    }

    protected byte[] generateRequest() throws OcspException {
        try {
            // Initiate OCSP Request Builder.
            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();


            // Create request for each certificate.
            for (X509Certificate certificate : certificates) {
                reqBuilder.addRequest(new CertificateID((new CertID(
                        algorithmIdentifier,
                        issuerNameHash,
                        issuerKeyHash,
                        new ASN1Integer(certificate.getSerialNumber())))));
            }

            if (extensions.size() > 0)
                reqBuilder.setRequestExtensions(new Extensions(extensions.toArray(new Extension[extensions.size()])));

            // Build OCSP Request.
            return reqBuilder.build().getEncoded();
        } catch (OCSPException | IOException e) {
            throw new OcspException("Exception while creating OCSP request: '%s'", e, e.getMessage());
        }
    }
}
