package com.threatloop.pipeline.ticketing;
import com.threatloop.pipeline.model.Threat;
public interface IssueTrackerClient {
    Ticket file(Threat threat) throws Exception;
}
