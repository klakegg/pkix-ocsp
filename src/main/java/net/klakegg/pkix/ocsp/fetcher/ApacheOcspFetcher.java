package net.klakegg.pkix.ocsp.fetcher;

import net.klakegg.pkix.ocsp.api.OcspFetcher;
import net.klakegg.pkix.ocsp.api.OcspFetcherResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * @author erlend
 */
public class ApacheOcspFetcher implements OcspFetcher {

    @Override
    public OcspFetcherResponse fetch(URI uri, byte[] content) throws IOException {
        HttpPost httpPost = new HttpPost(uri);
        httpPost.setEntity(new ByteArrayEntity(content));
        httpPost.setHeader("Content-Type", "application/ocsp-request");
        httpPost.setHeader("Accept", "application/ocsp-response");

        return new ApacheOcspFetcherResponse(getHttpClient().execute(httpPost));
    }

    protected CloseableHttpClient getHttpClient() {
        return HttpClients.createDefault();
    }

    private class ApacheOcspFetcherResponse implements OcspFetcherResponse {

        private CloseableHttpResponse response;

        public ApacheOcspFetcherResponse(CloseableHttpResponse response) {
            this.response = response;
        }

        @Override
        public int getStatus() {
            return response.getStatusLine().getStatusCode();
        }

        @Override
        public String getContentType() {
            return response.getFirstHeader("Content-Type").getValue();
        }

        @Override
        public InputStream getContent() throws IOException {
            return response.getEntity().getContent();
        }

        @Override
        public void close() throws IOException {
            response.close();
            response = null;
        }
    }
}
