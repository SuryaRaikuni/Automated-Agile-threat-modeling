package com.example.checkout.annotations;

import java.lang.annotation.*;

/**
 * Marks a class as a DFD Data Store node.
 * {@code encryptedAtRest="false"} → InfoDisclosureRule fires when the store
 * holds PII or sensitive data.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface DataStore {
    /** Whether data at rest is encrypted. "true" | "false" */
    String encryptedAtRest() default "false";

    /** Human-readable description shown in the DFD and dashboard. */
    String description() default "";
}
