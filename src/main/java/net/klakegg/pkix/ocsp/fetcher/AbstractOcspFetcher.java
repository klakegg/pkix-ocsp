package net.klakegg.pkix.ocsp.fetcher;

import net.klakegg.pkix.ocsp.api.OcspFetcher;
import net.klakegg.pkix.ocsp.builder.Properties;
import net.klakegg.pkix.ocsp.builder.Property;

/**
 * @author erlend
 */
abstract class AbstractOcspFetcher implements OcspFetcher {

    public static final Property<Integer> TIMEOUT_CONNECT = Property.create(15000);

    public static final Property<Integer> TIMEOUT_READ = Property.create(15000);

    protected final Properties properties;

    protected AbstractOcspFetcher(Properties properties) {
        this.properties = properties;
    }
}
