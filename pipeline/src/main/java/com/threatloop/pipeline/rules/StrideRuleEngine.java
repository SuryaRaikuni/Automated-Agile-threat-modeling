package com.threatloop.pipeline.rules;
import com.threatloop.pipeline.dfd.DataFlowDiagram;
import com.threatloop.pipeline.dfd.DfdElement;
import com.threatloop.pipeline.model.StrideCategory;
import com.threatloop.pipeline.model.Threat;

import java.util.*;

public class StrideRuleEngine {
    private final List<ThreatRule> rules;
    private final Set<StrideCategory> enabledCategories;

    public StrideRuleEngine(List<ThreatRule> rules) {
        this.rules = List.copyOf(rules);
        this.enabledCategories = new HashSet<>(Arrays.asList(StrideCategory.values()));
    }

    public StrideRuleEngine(List<ThreatRule> rules, Set<StrideCategory> enabledCategories) {
        this.rules = List.copyOf(rules);
        this.enabledCategories = Set.copyOf(enabledCategories);
    }

    public List<Threat> run(DataFlowDiagram dfd) {
        List<Threat> allThreats = new ArrayList<>();
        for (DfdElement element : dfd.elements()) {
            for (ThreatRule rule : rules) {
                if (enabledCategories.contains(rule.category())) {
                    allThreats.addAll(rule.evaluate(element, dfd));
                }
            }
        }
        return allThreats;
    }
}
