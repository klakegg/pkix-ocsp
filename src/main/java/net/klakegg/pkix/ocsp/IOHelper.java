package net.klakegg.pkix.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author erlend
 */
class IOHelper {

    public static byte[] toByteArray(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        byte[] buf = new byte[8192];
        int r;
        while ((r = inputStream.read(buf)) != -1) {
            outputStream.write(buf, 0, r);
        }

        return outputStream.toByteArray();
    }
}
