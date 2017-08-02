package net.klakegg.pkix.ocsp.fetcher;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

/**
 * @author erlend
 */
public class PooledApacheOcspFetcher extends ApacheOcspFetcher {

    protected PoolingHttpClientConnectionManager httpClientConnectionManager;

    public PooledApacheOcspFetcher() {
        this(new PoolingHttpClientConnectionManager());
    }

    public PooledApacheOcspFetcher(PoolingHttpClientConnectionManager httpClientConnectionManager) {
        this.httpClientConnectionManager = httpClientConnectionManager;
    }

    @Override
    protected CloseableHttpClient getHttpClient() {
        HttpClientBuilder httpClientBuilder = HttpClients.custom();

        // Connection pool
        httpClientBuilder.setConnectionManager(httpClientConnectionManager);
        httpClientBuilder.setConnectionManagerShared(true);

        // Use system default for proxy
        httpClientBuilder.useSystemProperties();

        return httpClientBuilder.build();
    }
}
