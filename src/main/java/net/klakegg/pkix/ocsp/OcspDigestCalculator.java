package net.klakegg.pkix.ocsp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Lightweight implementation of DigestCalculator with implementation of DigestOutputStream in one class.
 *
 * @author erlend
 */
class OcspDigestCalculator extends OutputStream implements DigestCalculator {

    private MessageDigest messageDigest;

    private ASN1ObjectIdentifier objectIdentifier;

    public OcspDigestCalculator(String algorithm, String objectIdentifier) {
        this(algorithm, new ASN1ObjectIdentifier(objectIdentifier));
    }

    public OcspDigestCalculator(String algorithm, ASN1ObjectIdentifier objectIdentifier) {
        try {
            this.messageDigest = MessageDigest.getInstance(algorithm);
            this.objectIdentifier = objectIdentifier;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    @Override
    public void write(int b) throws IOException {
        messageDigest.update((byte) b);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new AlgorithmIdentifier(objectIdentifier);
    }

    @Override
    public OutputStream getOutputStream() {
        return this;
    }

    @Override
    public byte[] getDigest() {
        return messageDigest.digest();
    }

    /**
     * Calculate hash for a given set of bytes.
     *
     * @param bytes Bytes provided for hashing.
     * @return Hash of provided bytes.
     * @throws IOException
     */
    public byte[] calculate(byte[] bytes) throws IOException {
        write(bytes);
        return getDigest();
    }
}
