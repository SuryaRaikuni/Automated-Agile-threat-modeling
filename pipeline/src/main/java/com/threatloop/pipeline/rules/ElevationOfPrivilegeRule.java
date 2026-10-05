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

public class ElevationOfPrivilegeRule implements ThreatRule {
    @Override
    public StrideCategory category() {
        return StrideCategory.ELEVATION_OF_PRIVILEGE;
    }

    @Override
    public List<Threat> evaluate(DfdElement element, DataFlowDiagram dfd) {
        if (element.type() == ElementType.PROCESS) {
            String priv = element.getAttribute("privilege", "");
            if ("elevated".equals(priv) || "admin".equals(priv)) {
                Threat t = Threat.of(
                    category(),
                    Severity.CRITICAL,
                    "Potential Privilege Escalation in " + element.name(),
                    "Process has elevated privileges.",
                    "Apply least-privilege principle and validate privilege transitions",
                    element.id(),
                    "unknown"
                );
                return List.of(t);
            }
        }
        return Collections.emptyList();
    }
}
