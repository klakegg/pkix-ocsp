package net.klakegg.pkix.ocsp.fetcher;

import net.klakegg.pkix.ocsp.api.OcspFetcher;
import net.klakegg.pkix.ocsp.api.OcspFetcherResponse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;

/**
 * @author erlend
 */
public class UrlOcspFetcher implements OcspFetcher {

    @Override
    public OcspFetcherResponse fetch(URI uri, byte[] content) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(15000);
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");

        try (OutputStream os = connection.getOutputStream()) {
            os.write(content);
        }

        return new UrlOcspFetcherResponse(connection);
    }

    private class UrlOcspFetcherResponse implements OcspFetcherResponse {

        private HttpURLConnection connection;

        public UrlOcspFetcherResponse(HttpURLConnection connection) {
            this.connection = connection;
        }

        @Override
        public int getStatus() throws IOException {
            return connection.getResponseCode();
        }

        @Override
        public String getContentType() {
            return connection.getContentType();
        }

        @Override
        public InputStream getContent() throws IOException {
            return connection.getInputStream();
        }

        @Override
        public void close() throws IOException {
            // No action.
        }
    }
}
