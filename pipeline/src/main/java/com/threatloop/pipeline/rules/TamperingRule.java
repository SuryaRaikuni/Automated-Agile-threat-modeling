package com.threatloop.pipeline.rules;
import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdEdge;
import com.threatloop.pipeline.dfd.DfdElement;
import com.threatloop.pipeline.model.Severity;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;

import java.util.ArrayList;
import java.util.List;

public class TamperingRule implements ThreatRule {
    @Override
    public StrideCategory category() {
        return StrideCategory.TAMPERING;
    }

    @Override
    public List<Threat> evaluate(DfdElement element, DataFlowDiagram dfd) {
        List<Threat> threats = new ArrayList<>();
        List<DfdEdge> edges = dfd.edgesFrom(element.id());
        for (DfdEdge edge : edges) {
            if (!edge.encrypted()) {
                Threat t = Threat.of(
                    category(),
                    Severity.HIGH,
                    "Unencrypted Data Flow from " + element.name() + " to " + edge.targetId(),
                    "Data flow to " + edge.targetId() + " is not encrypted.",
                    "Enforce TLS 1.2+ on all data flows",
                    element.id(),
                    "unknown"
                );
                threats.add(t);
            }
        }
        return threats;
    }
}
