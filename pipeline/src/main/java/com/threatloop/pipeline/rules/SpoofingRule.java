package com.threatloop.pipeline.rules;
import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdElement;
import com.threatloop.pipeline.dfd.ElementType;
import com.threatloop.pipeline.model.Severity;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;

import java.util.Collections;
import java.util.List;

public class SpoofingRule implements ThreatRule {
    @Override
    public StrideCategory category() {
        return StrideCategory.SPOOFING;
    }

    @Override
    public List<Threat> evaluate(DfdElement element, DataFlowDiagram dfd) {
        if (element.type() == ElementType.EXTERNAL_ENTITY || element.type() == ElementType.PROCESS) {
            if (!"true".equals(element.getAttribute("auth", "false"))) {
                Threat t = Threat.of(
                    category(),
                    Severity.HIGH,
                    "Missing Authentication on " + element.name(),
                    "Element lacks authentication.",
                    "Implement mutual TLS or token-based authentication",
                    element.id(),
                    "unknown"
                );
                return List.of(t);
            }
        }
        return Collections.emptyList();
    }
}
