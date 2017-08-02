package net.klakegg.pkix.ocsp.builder;

import java.util.Map;

/**
 * @author erlend
 */
public class Properties {

    private Map<Property<?>, Object> map;

    protected Properties(Map<Property<?>, Object> map) {
        this.map = map;
    }

    @SuppressWarnings("unchecked")
    public <S> S get(Property<S> property) {
        return map.containsKey(property) ? (S) map.get(property) : property.getDefaultValue();
    }
}
