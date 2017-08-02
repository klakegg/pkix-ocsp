package net.klakegg.pkix.ocsp.api;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author erlend
 */
public interface OcspFetcherResponse extends Closeable {

    int getStatus() throws IOException;

    String getContentType() throws IOException;

    InputStream getContent() throws IOException;

}
