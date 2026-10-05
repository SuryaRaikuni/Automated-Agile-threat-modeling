package com.threatloop.pipeline.ticketing;

import com.threatloop.pipeline.model.Threat;

import java.util.ArrayList;
import java.util.List;

public class TicketGenerator {
    private final IssueTrackerClient client;

    public TicketGenerator(IssueTrackerClient client) {
        this.client = client;
    }

    public List<Ticket> generateTickets(List<Threat> newThreats) {
        List<Ticket> tickets = new ArrayList<>();
        for (Threat threat : newThreats) {
            try {
                tickets.add(client.file(threat));
            } catch (Exception e) {
                throw new RuntimeException("Failed to file ticket for threat " + threat.id(), e);
            }
        }
        return tickets;
    }
}
