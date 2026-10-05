package com.example.checkout;

import com.example.checkout.annotations.ExternalEntity;

/**
 * External payment processor integration.
 *
 * <p><strong>Intentional threat surface (for demo/scanning):</strong>
 * <ul>
 *   <li>{@code auth="false"} — no mutual TLS or API-key validation configured.</li>
 *   <li>This triggers <em>SpoofingRule</em> in the ThreatLoop pipeline.</li>
 * </ul>
 */
@ExternalEntity(auth = "false", description = "External payment processor")
public class PaymentGateway {

    /**
     * Processes a payment stub.
     * In a real implementation this would call the payment-processor API over mTLS.
     *
     * @param amount    charge amount in USD
     * @param cardToken tokenised card reference (e.g. Stripe token)
     * @return {@code true} if the payment succeeded
     */
    public boolean processPayment(double amount, String cardToken) {
        // Stub — always succeeds in the sample project.
        // Missing: authentication header, mTLS certificate pinning.
        return true;
    }
}
