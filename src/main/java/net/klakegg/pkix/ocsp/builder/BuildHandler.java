package net.klakegg.pkix.ocsp.builder;

/**
 * @author erlend
 */
public interface BuildHandler<T> {

    T perform(Properties properties);

}
