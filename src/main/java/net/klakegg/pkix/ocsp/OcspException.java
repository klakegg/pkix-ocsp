package net.klakegg.pkix.ocsp;

/**
 * @author erlend
 */
public class OcspException extends Exception {

    protected static void trigger(Boolean trigger, String message, Object... objects) throws OcspException {
        if (trigger)
            throw new OcspException(message, objects);
    }

    public OcspException(String message, Object... objects) {
        super(String.format(message, objects));
    }

    public OcspException(String message, Throwable cause, Object... objects) {
        super(String.format(message, objects), cause);
    }
}
