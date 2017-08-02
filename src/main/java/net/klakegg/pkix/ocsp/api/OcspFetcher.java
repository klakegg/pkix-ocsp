package net.klakegg.pkix.ocsp.api;

import java.io.IOException;
import java.net.URI;

/**
 * @author erlend
 */
public interface OcspFetcher {

    OcspFetcherResponse fetch(URI uri, byte[] content) throws IOException;

}
