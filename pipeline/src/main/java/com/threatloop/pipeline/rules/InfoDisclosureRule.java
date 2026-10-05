package com.threatloop.pipeline.rules;
import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdElement;
import com.threatloop.pipeline.dfd.ElementType;
import com.threatloop.pipeline.model.Severity;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;

import java.util.Collections;
import java.util.List;

public class InfoDisclosureRule implements ThreatRule {
    @Override
    public StrideCategory category() {
        return StrideCategory.INFO_DISCLOSURE;
    }

    @Override
    public List<Threat> evaluate(DfdElement element, DataFlowDiagram dfd) {
        if (element.type() == ElementType.DATA_STORE) {
            if (!"true".equals(element.getAttribute("encryptedAtRest", "false"))) {
                Threat t = Threat.of(
                    category(),
                    Severity.CRITICAL,
                    "Sensitive Data Store Not Encrypted at Rest: " + element.name(),
                    "Data store lacks encryption at rest.",
                    "Enable encryption at rest using AES-256",
                    element.id(),
                    "unknown"
                );
                return List.of(t);
            }
        }
        return Collections.emptyList();
    }
}
