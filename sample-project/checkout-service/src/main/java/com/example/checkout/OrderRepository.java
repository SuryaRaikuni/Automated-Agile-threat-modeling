package com.example.checkout;

import com.example.checkout.annotations.DataStore;

/**
 * Persistence layer for orders and customer PII.
 *
 * <p><strong>Intentional threat surface (for demo/scanning):</strong>
 * <ul>
 *   <li>{@code encryptedAtRest="false"} — PII stored in plaintext.</li>
 *   <li>This triggers <em>InfoDisclosureRule</em> in the ThreatLoop pipeline.</li>
 * </ul>
 *
 * <p>Fields stored per order: customer name, shipping address, card last-4.
 */
@DataStore(encryptedAtRest = "false", description = "Order and PII data store")
public class OrderRepository {

    /**
     * Persists an order alongside customer PII.
     * Missing: field-level encryption before write.
     *
     * @param orderId     unique order identifier
     * @param customerPii serialised customer PII (name, address, card last-4)
     */
    public void save(String orderId, String customerPii) {
        // Stub — prints to stdout; no database in the sample project.
        System.out.println("Saving order " + orderId);
    }

    /**
     * Retrieves a previously saved order.
     *
     * @param orderId unique order identifier
     * @return serialised order record, or {@code null} if not found
     */
    public String findOrder(String orderId) {
        return null; // stub
    }
}
