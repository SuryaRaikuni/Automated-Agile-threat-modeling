package com.threatloop.pipeline.ticketing;

import com.threatloop.pipeline.model.Severity;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class TicketGeneratorTest {

    @Test
    void singleThreatCallsClientOnce() throws Exception {
        IssueTrackerClient mockClient = mock(IssueTrackerClient.class);
        Threat t = Threat.of(StrideCategory.SPOOFING, Severity.HIGH, "T1", "D1", "M1", "e1", "r1");
        Ticket ticket = new Ticket(t.id(), "1", "url", "OPEN");
        when(mockClient.file(any(Threat.class))).thenReturn(ticket);

        TicketGenerator gen = new TicketGenerator(mockClient);
        List<Ticket> res = gen.generateTickets(List.of(t));

        verify(mockClient, times(1)).file(t);
        assertEquals(1, res.size());
    }

    @Test
    void threeThreatsMakeThreeCalls() throws Exception {
        IssueTrackerClient mockClient = mock(IssueTrackerClient.class);
        Threat t1 = Threat.of(StrideCategory.SPOOFING, Severity.HIGH, "T1", "D1", "M1", "e1", "r1");
        Threat t2 = Threat.of(StrideCategory.TAMPERING, Severity.HIGH, "T2", "D2", "M2", "e2", "r1");
        Threat t3 = Threat.of(StrideCategory.REPUDIATION, Severity.HIGH, "T3", "D3", "M3", "e3", "r1");
        
        when(mockClient.file(any(Threat.class))).thenReturn(new Ticket("id", "1", "url", "OPEN"));

        TicketGenerator gen = new TicketGenerator(mockClient);
        gen.generateTickets(List.of(t1, t2, t3));

        verify(mockClient, times(3)).file(any(Threat.class));
    }

    @Test
    void clientExceptionWrapsInRuntimeException() throws Exception {
        IssueTrackerClient mockClient = mock(IssueTrackerClient.class);
        Threat t = Threat.of(StrideCategory.SPOOFING, Severity.HIGH, "T1", "D1", "M1", "e1", "r1");
        
        when(mockClient.file(any(Threat.class))).thenThrow(new Exception("API Error"));

        TicketGenerator gen = new TicketGenerator(mockClient);
        
        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            gen.generateTickets(List.of(t));
        });
        
        assertTrue(ex.getMessage().contains(t.id()));
    }
}
