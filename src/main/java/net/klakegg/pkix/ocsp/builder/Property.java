package net.klakegg.pkix.ocsp.builder;

/**
 * @author erlend
 */
public class Property<T> {

    private final T defaultValue;

    public static <T> Property<T> create() {
        return new Property<>(null);
    }

    public static <T> Property<T> create(T defaultValue) {
        return new Property<>(defaultValue);
    }

    private Property(T defaultValue) {
        this.defaultValue = defaultValue;
    }

    public T getDefaultValue() {
        return defaultValue;
    }

}
