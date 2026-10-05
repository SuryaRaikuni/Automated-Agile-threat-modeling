package com.threatloop.pipeline.rules;
import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdElement;
import com.threatloop.pipeline.dfd.ElementType;
import com.threatloop.pipeline.model.Severity;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;

import java.util.Collections;
import java.util.List;

public class RepudiationRule implements ThreatRule {
    @Override
    public StrideCategory category() {
        return StrideCategory.REPUDIATION;
    }

    @Override
    public List<Threat> evaluate(DfdElement element, DataFlowDiagram dfd) {
        if (element.type() == ElementType.PROCESS) {
            if (!"true".equals(element.getAttribute("logging", "false"))) {
                Threat t = Threat.of(
                    category(),
                    Severity.MEDIUM,
                    "Missing Audit Logging in " + element.name(),
                    "No audit logging found.",
                    "Implement structured audit logging for all state-changing operations",
                    element.id(),
                    "unknown"
                );
                return List.of(t);
            }
        }
        return Collections.emptyList();
    }
}
