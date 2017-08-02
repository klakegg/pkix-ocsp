package net.klakegg.pkix.ocsp;

/**
 * Certificate status provided by OCSP responder.
 *
 * @author erlend
 */
public enum OcspStatus {

    /**
     * The certificate is valid.
     */
    GOOD,

    /**
     * The certificate is temporarily or permanently revoked.
     */
    REVOKED,

    UNKNOWN

}
