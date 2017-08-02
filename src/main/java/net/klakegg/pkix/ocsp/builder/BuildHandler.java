package net.klakegg.pkix.ocsp.builder;

/**
 * @author erlend
 */
public interface BuildHandler<T> {

    T build(Properties properties);

}
