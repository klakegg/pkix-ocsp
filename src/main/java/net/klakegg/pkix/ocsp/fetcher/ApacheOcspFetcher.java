package net.klakegg.pkix.ocsp.fetcher;

import net.klakegg.pkix.ocsp.api.OcspFetcher;
import net.klakegg.pkix.ocsp.api.OcspFetcherResponse;
import net.klakegg.pkix.ocsp.builder.BuildHandler;
import net.klakegg.pkix.ocsp.builder.Builder;
import net.klakegg.pkix.ocsp.builder.Properties;
import net.klakegg.pkix.ocsp.builder.Property;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

/**
 * @author erlend
 */
public class ApacheOcspFetcher extends AbstractOcspFetcher {

    public static final Property<HttpClientConnectionManager> CONNECTION_MANAGER = Property.create();

    public static final Property<Boolean> CONNECTION_MANAGER_SHARED = Property.create(false);

    public static final Property<Integer> TIMEOUT_CONNECTION_MANAGER = Property.create(-1);

    /**
     * Builder to create an instance of OcspFetcher using Apache HttpClient for connectivity.
     *
     * @return Prepared fetcher.
     */
    public static Builder<OcspFetcher> builder() {
        return new Builder<>(new BuildHandler<OcspFetcher>() {
            @Override
            public OcspFetcher build(Properties properties) {
                return new ApacheOcspFetcher(properties);
            }
        });
    }

    private ApacheOcspFetcher(Properties properties) {
        super(properties);
    }

    @Override
    public OcspFetcherResponse fetch(URI uri, byte[] content) throws IOException {
        HttpPost httpPost = new HttpPost(uri);
        httpPost.setHeader("Content-Type", "application/ocsp-request");
        httpPost.setHeader("Accept", "application/ocsp-response");
        httpPost.setEntity(new ByteArrayEntity(content));
        httpPost.setConfig(getRequestConfig());

        return new ApacheOcspFetcherResponse(getHttpClient().execute(httpPost));
    }

    protected CloseableHttpClient getHttpClient() {
        return HttpClientBuilder.create()
                .setConnectionManager(properties.get(CONNECTION_MANAGER))
                .setConnectionManagerShared(properties.get(CONNECTION_MANAGER_SHARED))
                .build();
    }

    protected RequestConfig getRequestConfig() {
        return RequestConfig.custom()
                .setConnectTimeout(properties.get(TIMEOUT_CONNECT))
                .setSocketTimeout(properties.get(TIMEOUT_READ))
                .setConnectionRequestTimeout(properties.get(TIMEOUT_CONNECTION_MANAGER))
                .build();
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
