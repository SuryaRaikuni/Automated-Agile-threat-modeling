package com.example.checkout.annotations;

import java.lang.annotation.*;

/**
 * Marks a class as a DFD External Entity.
 * The ThreatLoop DfdExtractor reads {@code auth} to detect missing authentication
 * and flags it for the SpoofingRule.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface ExternalEntity {
    /** Whether the entity authenticates callers. "true" | "false" */
    String auth() default "false";

    /** Human-readable description shown in the DFD and dashboard. */
    String description() default "";
}
