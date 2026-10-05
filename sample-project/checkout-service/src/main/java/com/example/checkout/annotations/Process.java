package com.example.checkout.annotations;

import java.lang.annotation.*;

/**
 * Marks a class as a DFD Process node.
 * <ul>
 *   <li>{@code logging="false"} → RepudiationRule fires</li>
 *   <li>{@code rateLimit="false"} → DenialOfServiceRule fires</li>
 * </ul>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Process {
    /** Whether the process emits audit/access logs. "true" | "false" */
    String logging() default "false";

    /** Whether the process enforces rate limiting. "true" | "false" */
    String rateLimit() default "false";

    /** Human-readable description shown in the DFD and dashboard. */
    String description() default "";
}
