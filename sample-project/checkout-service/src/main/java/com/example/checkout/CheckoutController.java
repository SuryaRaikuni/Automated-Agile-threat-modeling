package com.example.checkout;

import com.example.checkout.annotations.Process;

/**
 * REST endpoint for checkout operations.
 *
 * <p><strong>Intentional threat surface (for demo/scanning):</strong>
 * <ul>
 *   <li>{@code logging="false"} — no audit log written → triggers <em>RepudiationRule</em>.</li>
 *   <li>{@code rateLimit="false"} — unlimited requests accepted → triggers <em>DenialOfServiceRule</em>.</li>
 *   <li>Unencrypted data flow to {@link OrderRepository} → triggers <em>TamperingRule</em>.</li>
 * </ul>
 *
 * <p>In a production implementation this class would:
 * <ol>
 *   <li>Write a structured audit log entry before every mutation.</li>
 *   <li>Apply a token-bucket rate limiter per {@code customerId}.</li>
 *   <li>Transmit data to the repository over an encrypted channel.</li>
 * </ol>
 */
@Process(logging = "false", rateLimit = "false", description = "Checkout REST endpoint")
public class CheckoutController {

    private final OrderRepository orderRepository = new OrderRepository();
    private final PaymentGateway paymentGateway   = new PaymentGateway();

    /**
     * Executes the checkout flow: charge → persist order.
     *
     * @param customerId caller-supplied customer identifier (untrusted)
     * @param amount     charge amount in USD
     * @return {@code "OK"} on success, {@code "FAILED"} otherwise
     */
    public String checkout(String customerId, double amount) {
        // Missing: audit log, rate-limit check, input validation.
        boolean paid = paymentGateway.processPayment(amount, "tok_stub");
        if (paid) {
            orderRepository.save("order-" + System.currentTimeMillis(), customerId);
            return "OK";
        }
        return "FAILED";
    }
}
