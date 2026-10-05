package com.threatloop.pipeline.rules;

import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdEdge;
import com.threatloop.pipeline.dfd.DfdElement;
import com.threatloop.pipeline.dfd.ElementType;
import com.threatloop.pipeline.model.Severity;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class StrideRuleEngineTest {

    @Test
    void engineWithNoRulesReturnsEmptyList() {
        StrideRuleEngine engine = new StrideRuleEngine(Collections.emptyList());
        DataFlowDiagram dfd = new DataFlowDiagram(List.of(new DfdElement("id", "name", ElementType.PROCESS, Map.of())), Collections.emptyList());
        assertEquals(0, engine.run(dfd).size());
    }

    @Test
    void spoofingRuleFiresOnUnauthenticatedExternalEntity() {
        StrideRuleEngine engine = new StrideRuleEngine(List.of(new SpoofingRule()));
        DfdElement element = new DfdElement("ext-1", "Ext", ElementType.EXTERNAL_ENTITY, Map.of());
        DataFlowDiagram dfd = new DataFlowDiagram(List.of(element), Collections.emptyList());
        List<Threat> threats = engine.run(dfd);
        assertEquals(1, threats.size());
        assertEquals(StrideCategory.SPOOFING, threats.get(0).category());
    }

    @Test
    void spoofingRuleDoesNotFireWhenAuthPresent() {
        StrideRuleEngine engine = new StrideRuleEngine(List.of(new SpoofingRule()));
        DfdElement element = new DfdElement("ext-1", "Ext", ElementType.EXTERNAL_ENTITY, Map.of("auth", "true"));
        DataFlowDiagram dfd = new DataFlowDiagram(List.of(element), Collections.emptyList());
        assertEquals(0, engine.run(dfd).size());
    }

    @Test
    void tamperingRuleFiresOnUnencryptedEdge() {
        StrideRuleEngine engine = new StrideRuleEngine(List.of(new TamperingRule()));
        DfdElement proc = new DfdElement("proc-1", "Proc", ElementType.PROCESS, Map.of());
        DfdEdge edge = new DfdEdge("edge-1", "proc-1", "tgt-1", "HTTP", false);
        DataFlowDiagram dfd = new DataFlowDiagram(List.of(proc), List.of(edge));
        List<Threat> threats = engine.run(dfd);
        assertEquals(1, threats.size());
        assertEquals(StrideCategory.TAMPERING, threats.get(0).category());
    }

    @Test
    void disabledCategoryProducesNoThreats() {
        Set<StrideCategory> enabled = new HashSet<>(Arrays.asList(StrideCategory.values()));
        enabled.remove(StrideCategory.SPOOFING);
        StrideRuleEngine engine = new StrideRuleEngine(List.of(new SpoofingRule()), enabled);
        DfdElement element = new DfdElement("ext-1", "Ext", ElementType.EXTERNAL_ENTITY, Map.of());
        DataFlowDiagram dfd = new DataFlowDiagram(List.of(element), Collections.emptyList());
        assertEquals(0, engine.run(dfd).size());
    }

    @Test
    void addingNewRuleClassNeverModifiesEngine() {
        class TestRule implements ThreatRule {
            @Override
            public StrideCategory category() { return StrideCategory.INFO_DISCLOSURE; }
            @Override
            public List<Threat> evaluate(DfdElement element, DataFlowDiagram dfd) {
                return List.of(Threat.of(StrideCategory.INFO_DISCLOSURE, Severity.INFORMATIONAL, "Test", "Desc", "Mitig", element.id(), "run1"));
            }
        }
        StrideRuleEngine engine = new StrideRuleEngine(List.of(new TestRule()));
        DfdElement element = new DfdElement("proc-1", "Proc", ElementType.PROCESS, Map.of());
        DataFlowDiagram dfd = new DataFlowDiagram(List.of(element), Collections.emptyList());
        List<Threat> threats = engine.run(dfd);
        assertEquals(1, threats.size());
        assertEquals("Test", threats.get(0).title());
    }
}
