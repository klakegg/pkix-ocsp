package net.klakegg.pkix.ocsp;

import net.klakegg.pkix.ocsp.api.OcspFetcher;
import net.klakegg.pkix.ocsp.api.OcspFetcherResponse;
import net.klakegg.pkix.ocsp.builder.Properties;
import net.klakegg.pkix.ocsp.builder.Property;
import net.klakegg.pkix.ocsp.fetcher.UrlOcspFetcher;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * This abstract class implements common features related to OCSP verification.
 *
 * @author erlend
 */
class AbstractOcspClient {

    public static final Property<String> DIGEST_ALGORITHM = Property.create("SHA-1");

    public static final Property<String> DIGEST_OBJECT_IDENTIFIER = Property.create("1.3.14.3.2.26");

    public static final Property<Boolean> EXCEPTION_ON_NO_PATH = Property.create(false);

    public static final Property<OcspFetcher> FETCHER = Property.create((OcspFetcher) new UrlOcspFetcher());

    public static final Property<List<X509Certificate>> INTERMEDIATES =
            Property.create(Collections.<X509Certificate>emptyList());

    public static final Property<URI> OVERRIDE_URL = Property.create();

    public static final Property<Boolean> NONCE = Property.create(true);

    /**
     * Properties provided by the builder.
     */
    protected final Properties properties;

    /**
     * Constructor accepting properties provided by the builder.
     *
     * @param properties Properties provided by the builder.
     */
    protected AbstractOcspClient(Properties properties) {
        this.properties = properties;
    }

    /**
     * Method for finding issuer by provided issuers in properties given an issued certificate.
     *
     * @param certificate Issued certificate.
     * @return Issuer of the issued certificate.
     * @throws OcspException Thrown when no issuer is found.
     */
    protected X509Certificate findIntermediate(X509Certificate certificate) throws OcspException {
        for (X509Certificate issuer : properties.get(INTERMEDIATES))
            if (issuer.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()))
                return issuer;

        throw new OcspException("Unable to find issuer '%s'.", certificate.getIssuerX500Principal().getName());
    }

    protected URI detectOcspUri(X509Certificate certificate) throws OcspException {
        byte[] extensionValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        if (extensionValue == null) {
            OcspException.trigger(properties.get(EXCEPTION_ON_NO_PATH),
                    "Unable to detect path for OCSP (%s)", Extension.authorityInfoAccess.getId());
            return null;
        }

        try {
            ASN1Sequence asn1Seq = (ASN1Sequence) X509ExtensionUtil.fromExtensionValue(extensionValue);
            Enumeration<?> objects = asn1Seq.getObjects();

            while (objects.hasMoreElements()) {
                ASN1Sequence obj = (ASN1Sequence) objects.nextElement();
                if (obj.getObjectAt(0).equals(X509ObjectIdentifiers.id_ad_ocsp)) {
                    DERTaggedObject location = (DERTaggedObject) obj.getObjectAt(1);
                    if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        DEROctetString uri = (DEROctetString) location.getObject();
                        return URI.create(new String(uri.getOctets()));
                    }
                }
            }
        } catch (Exception e) {
            throw new OcspException("Exception when reading AIA: '%s'.", e, e.getMessage());
        }

        OcspException.trigger(properties.get(EXCEPTION_ON_NO_PATH),
                "Unable to detect path for OCSP in AIA (%s)", Extension.authorityInfoAccess.getId());
        return null;
    }

    protected OCSPReq generateRequest(X509Certificate issuer, X509Certificate... certificates) throws OcspException {
        try {
            // Initiate OCSP Request Builder.
            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();

            // Digest calculator to be used to create values for the issuer certificate.
            // This is done once in case of multiple requests.
            OcspDigestCalculator digestCalculator = new OcspDigestCalculator(
                    properties.get(DIGEST_ALGORITHM),
                    properties.get(DIGEST_OBJECT_IDENTIFIER));

            // Create an instance of the issuer certificate for use with Bouncy Caste/ASN1.
            X509CertificateHolder issuerHolder = BCHelper.convertToHolder(issuer);

            // Calculate hashes to identify issuer certificate.
            ASN1OctetString issuerNameHash = new DEROctetString(
                    digestCalculator.calculate(issuerHolder.toASN1Structure().getSubject().getEncoded(ASN1Encoding.DER)));
            ASN1OctetString issuerKeyHash = new DEROctetString(
                    digestCalculator.calculate(issuerHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));

            // Create request for each certificate.
            for (X509Certificate certificate : certificates) {
                reqBuilder.addRequest(new CertificateID((new CertID(
                        digestCalculator.getAlgorithmIdentifier(),
                        issuerNameHash,
                        issuerKeyHash,
                        new ASN1Integer(certificate.getSerialNumber())))));
            }

            List<Extension> extensions = new ArrayList<>();

            if (properties.get(NONCE)) {
                byte[] nonce = new byte[16];
                ThreadLocalRandom.current().nextBytes(nonce);
                extensions.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString(nonce)));
            }

            if (extensions.size() > 0)
                reqBuilder.setRequestExtensions(new Extensions(extensions.toArray(new Extension[extensions.size()])));

            // Build OCSP Request.
            return reqBuilder.build();
        } catch (IOException | CertificateEncodingException | OCSPException e) {
            throw new OcspException("Exception when creating OCSP request: '%s'", e, e.getMessage());
        }
    }

    protected OCSPResp fetch(OCSPReq ocspReq, URI uri) throws OcspException {
        try (OcspFetcherResponse response = properties.get(FETCHER).fetch(uri, ocspReq.getEncoded())) {
            if (response.getStatus() != 200)
                throw new OcspException("Received HTTP code '%s' from responder.", response.getStatus());

            if (!response.getContentType().equalsIgnoreCase("application/ocsp-response"))
                throw new OcspException("Response was of type '%s'.", response.getContentType());

            try (InputStream inputStream = response.getContent()) {
                return new OCSPResp(IOHelper.toByteArray(inputStream));
            }
        } catch (IOException e) {
            throw new OcspException(e.getMessage(), e);
        }
    }

    protected void verifyResponse(OCSPResp response) throws OcspException {
        switch (response.getStatus()) {
            case OCSPResponseStatus.SUCCESSFUL:
                break;
            case OCSPResponseStatus.MALFORMED_REQUEST:
                throw new OcspException("Request was malformed.");
            case OCSPResponseStatus.INTERNAL_ERROR:
                throw new OcspException("An internal error occurred in the OCSP Server.");
            case OCSPResponseStatus.TRY_LATER:
                throw new OcspException("OCSP server is currently too busy.");
            case OCSPResponseStatus.SIG_REQUIRED:
                throw new OcspException("Signed request is required for this OCSP Server.");
            case OCSPResponseStatus.UNAUTHORIZED:
                throw new OcspException("Your signature was not authorized by the OCSP Server.");
            default:
                throw new OcspException("Unknown OCSPResponse status code '%s'.", response.getStatus());
        }
    }

    protected OcspResult parseResponseObject(OCSPResp ocspResp) throws OcspException {
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

        Map<BigInteger, OcspResponse> map = new HashMap<>();

        for (SingleResp singleResponse : response.getResponses()) {
            map.put(singleResponse.getCertID().getSerialNumber(), new OcspResponse(
                    parseCertificateStatus(singleResponse.getCertStatus()),
                    singleResponse.getThisUpdate(),
                    singleResponse.getNextUpdate()
            ));
        }

        return new OcspResult(map);
    }

    protected OcspStatus parseCertificateStatus(CertificateStatus certificateStatus) {
        if (certificateStatus == null)
            return OcspStatus.GOOD;
        else if (certificateStatus instanceof RevokedStatus)
            return OcspStatus.REVOKED;
        else // if (certificateStatus instanceof UnknownStatus)
            return OcspStatus.UNKNOWN;
    }
}
