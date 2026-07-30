package systems.hugmesh.forumbff.config;

import io.r2dbc.spi.ConnectionFactory;
import org.springframework.boot.data.r2dbc.autoconfigure.DataR2dbcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.r2dbc.convert.R2dbcCustomConversions;
import org.springframework.data.r2dbc.dialect.DialectResolver;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;

/**
 * R2DBC type-conversion shims for the forum BFF's Postgres (and H2 slice-test) data
 * sources. Copied from the user-bff / federation-api {@code R2dbcConvertersConfig}.
 *
 * <h2>Why these shims are needed</h2>
 *
 * <p>The Postgres R2DBC driver returns {@code OffsetDateTime} for {@code timestamptz}
 * columns and {@code LocalDateTime} for plain {@code timestamp} columns, but the entity
 * records ({@link systems.hugmesh.forumbff.forum.ForumAction ForumAction},
 * {@link systems.hugmesh.forumbff.forum.ForumUserRole ForumUserRole}) declare their
 * timestamp fields as {@link java.time.Instant Instant}. Spring Data R2DBC's reflective
 * JSR-310 fallback converters are silently skipped under GraalVM native-image AOT
 * compilation, so registering the two reading converters explicitly keeps the conversion
 * deterministic in both JVM and native-image modes. The H2 in-memory database used by
 * slice tests also returns {@code LocalDateTime} for {@code timestamp} columns, so the
 * same converters serve the test layer without extra wiring.
 *
 * @see systems.hugmesh.forumbff.config.NativeHintsConfig
 */
@Configuration(proxyBeanMethods = false)
public class R2dbcConvertersConfig {

    /**
     * Replaces the auto-configured {@link R2dbcCustomConversions} bean
     * (see {@link DataR2dbcAutoConfiguration}) with the dialect defaults plus the
     * two explicit timestamp reading converters needed for JVM and native-image modes.
     *
     * @param connectionFactory the R2DBC connection factory used to resolve the
     *                          active dialect and its built-in converters
     * @return a {@link R2dbcCustomConversions} instance that maps
     *         {@code OffsetDateTime} and {@code LocalDateTime} to {@link Instant}
     */
    @Bean
    public R2dbcCustomConversions r2dbcCustomConversions(ConnectionFactory connectionFactory) {
        var dialect = DialectResolver.getDialect(connectionFactory);
        var converters = new ArrayList<Object>(dialect.getConverters());
        converters.add(new OffsetDateTimeToInstantConverter());
        converters.add(new LocalDateTimeToInstantConverter());
        return R2dbcCustomConversions.of(dialect, converters);
    }

    /**
     * Reading converter: maps the {@code OffsetDateTime} the Postgres R2DBC driver
     * returns for {@code timestamptz} columns to the {@link Instant} the entity
     * records declare.
     */
    @ReadingConverter
    static class OffsetDateTimeToInstantConverter implements Converter<OffsetDateTime, Instant> {
        /**
         * @param source the {@code OffsetDateTime} read from the Postgres column
         * @return the equivalent {@link Instant} (UTC epoch)
         */
        @Override public Instant convert(OffsetDateTime source) { return source.toInstant(); }
    }

    /**
     * Reading converter: maps the {@code LocalDateTime} the Postgres R2DBC driver
     * returns for plain {@code timestamp} columns — and the H2 driver returns for
     * all timestamp columns in slice tests — to {@link Instant} (treating the value
     * as UTC, which is the convention for all timestamp columns in this schema).
     */
    @ReadingConverter
    static class LocalDateTimeToInstantConverter implements Converter<LocalDateTime, Instant> {
        /**
         * @param source the {@code LocalDateTime} read from the column (assumed UTC)
         * @return the equivalent {@link Instant} pinned to {@link ZoneOffset#UTC}
         */
        @Override public Instant convert(LocalDateTime source) { return source.toInstant(ZoneOffset.UTC); }
    }
}
