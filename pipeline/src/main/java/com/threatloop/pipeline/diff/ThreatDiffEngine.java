package com.threatloop.pipeline.diff;

import com.threatloop.pipeline.model.Threat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class ThreatDiffEngine {
    /**
     * Returns only NEW threats (id not in previous) plus CHANGED threats
     * (same id but different severity or description).
     * Threats in previous but absent from current are returned with status="RESOLVED".
     */
    public DiffResult diff(List<Threat> current, List<Threat> previous) {
        Map<String, Threat> previousMap = previous.stream().collect(Collectors.toMap(Threat::id, Function.identity()));
        Map<String, Threat> currentMap = current.stream().collect(Collectors.toMap(Threat::id, Function.identity()));

        List<Threat> newThreats = new ArrayList<>();
        List<Threat> changedThreats = new ArrayList<>();
        List<Threat> resolvedThreats = new ArrayList<>();

        for (Threat t : current) {
            if (!previousMap.containsKey(t.id())) {
                newThreats.add(t);
            } else {
                Threat prev = previousMap.get(t.id());
                if (prev.severity() != t.severity() || !prev.description().equals(t.description())) {
                    changedThreats.add(t);
                }
            }
        }

        for (Threat prev : previous) {
            if (!currentMap.containsKey(prev.id())) {
                resolvedThreats.add(prev.withStatus("RESOLVED"));
            }
        }

        return new DiffResult(newThreats, changedThreats, resolvedThreats);
    }
}
