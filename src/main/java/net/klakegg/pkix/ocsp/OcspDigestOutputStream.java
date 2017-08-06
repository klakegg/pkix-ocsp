package net.klakegg.pkix.ocsp;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Lightweight implementation of digest calculation simply extending OutputStream.
 *
 * @author erlend
 */
class OcspDigestOutputStream extends OutputStream {

    private MessageDigest messageDigest;

    public OcspDigestOutputStream(String algorithm) {
        try {
            this.messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    @Override
    public void write(int b) throws IOException {
        messageDigest.update((byte) b);
    }

    /**
     * Returns and resets the digest.
     *
     * @return Digest of content passed to write() since last reset.
     */
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
