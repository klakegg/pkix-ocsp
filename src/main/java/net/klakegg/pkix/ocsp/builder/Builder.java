package net.klakegg.pkix.ocsp.builder;

import java.util.HashMap;
import java.util.Map;

/**
 * @author erlend
 */
public class Builder<T> {

    protected BuildHandler<T> buildHandler;

    protected Map<Property<?>, Object> map = new HashMap<>();

    public Builder(BuildHandler<T> buildHandler) {
        this(buildHandler, new HashMap<Property<?>, Object>());
    }

    private Builder(BuildHandler<T> buildHandler, Map<Property<?>, Object> map) {
        this.buildHandler = buildHandler;
        this.map = map;
    }

    public <S> Builder<T> set(Property<S> property, S value) {
        Map<Property<?>, Object> map = new HashMap<>(this.map);
        map.put(property, value);

        return new Builder<>(buildHandler, map);
    }

    public T build() {
        return buildHandler.build(new Properties(map));
    }
}
