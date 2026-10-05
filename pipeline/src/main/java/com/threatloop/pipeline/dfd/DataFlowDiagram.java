package com.threatloop.pipeline.dfd;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public record DataFlowDiagram(List<DfdElement> elements, List<DfdEdge> edges) {
    public List<DfdEdge> edgesFrom(String elementId) {
        return edges.stream().filter(e -> e.sourceId().equals(elementId)).collect(Collectors.toList());
    }
    
    public List<DfdEdge> edgesTo(String elementId) {
        return edges.stream().filter(e -> e.targetId().equals(elementId)).collect(Collectors.toList());
    }
    
    public Optional<DfdElement> findElement(String id) {
        return elements.stream().filter(e -> e.id().equals(id)).findFirst();
    }
}
