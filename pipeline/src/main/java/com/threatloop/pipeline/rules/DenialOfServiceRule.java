package com.threatloop.pipeline.rules;
import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdEdge;
import com.threatloop.pipeline.dfd.DfdElement;
import com.threatloop.pipeline.dfd.ElementType;
import com.threatloop.pipeline.model.Severity;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;

import java.util.Collections;
import java.util.List;

public class DenialOfServiceRule implements ThreatRule {
    @Override
    public StrideCategory category() {
        return StrideCategory.DENIAL_OF_SERVICE;
    }

    @Override
    public List<Threat> evaluate(DfdElement element, DataFlowDiagram dfd) {
        if (element.type() == ElementType.PROCESS) {
            boolean hasExternalSource = dfd.edgesTo(element.id()).stream().anyMatch(edge -> {
                return dfd.findElement(edge.sourceId()).map(src -> src.type() == ElementType.EXTERNAL_ENTITY).orElse(false);
            });
            if (hasExternalSource && !"true".equals(element.getAttribute("rateLimit", "false"))) {
                Threat t = Threat.of(
                    category(),
                    Severity.MEDIUM,
                    "No Rate Limiting on " + element.name(),
                    "Process exposed to external entities without rate limiting.",
                    "Implement rate limiting and circuit breakers",
                    element.id(),
                    "unknown"
                );
                return List.of(t);
            }
        }
        return Collections.emptyList();
    }
}
