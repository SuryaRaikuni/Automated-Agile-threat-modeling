package com.threatloop.pipeline.rules;
import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdElement;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;
import java.util.List;

public interface ThreatRule {
    StrideCategory category();
    List<Threat> evaluate(DfdElement element, DataFlowDiagram dfd);
}
