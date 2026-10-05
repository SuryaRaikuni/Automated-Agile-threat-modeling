package com.threatloop.pipeline.dfd;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DfdExtractor {

    private static final Pattern CLASS_PATTERN = Pattern.compile("public\\s+(class|interface)\\s+([A-Za-z0-9_]+)");
    private static final Pattern ATTR_PATTERN = Pattern.compile("([a-zA-Z0-9_]+)\\s*=\\s*\\\"([a-zA-Z0-9_]+)\\\"");

    public DataFlowDiagram extract(Path projectRoot) throws IOException {
        List<DfdElement> elements = new ArrayList<>();
        List<DfdEdge> edges = new ArrayList<>();
        Map<String, String> classNameToId = new HashMap<>();
        Map<String, String> fileContentMap = new HashMap<>();

        if (!Files.exists(projectRoot)) {
            return new DataFlowDiagram(elements, edges);
        }

        try (Stream<Path> paths = Files.walk(projectRoot)) {
            List<Path> javaFiles = paths
                .filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".java"))
                .collect(Collectors.toList());

            for (Path p : javaFiles) {
                String content = Files.readString(p);
                Matcher m = CLASS_PATTERN.matcher(content);
                if (m.find()) {
                    String className = m.group(2);
                    String id = className.toLowerCase().replace(" ", "-");
                    classNameToId.put(className, id);
                    fileContentMap.put(className, content);

                    ElementType type = ElementType.PROCESS; // default
                    if (content.contains("@ExternalEntity")) type = ElementType.EXTERNAL_ENTITY;
                    else if (content.contains("@Process")) type = ElementType.PROCESS;
                    else if (content.contains("@DataStore")) type = ElementType.DATA_STORE;
                    else if (content.contains("@TrustBoundary")) type = ElementType.TRUST_BOUNDARY;
                    else if (className.endsWith("Controller") || className.endsWith("Resource")) type = ElementType.PROCESS;
                    else if (className.endsWith("Repository") || className.endsWith("Dao") || className.endsWith("DAO")) type = ElementType.DATA_STORE;
                    else if (className.endsWith("Gateway") || className.endsWith("Client") || className.endsWith("External")) type = ElementType.EXTERNAL_ENTITY;

                    Map<String, String> attributes = new HashMap<>();
                    Matcher attrMatcher = ATTR_PATTERN.matcher(content);
                    while (attrMatcher.find()) {
                        attributes.put(attrMatcher.group(1), attrMatcher.group(2));
                    }

                    elements.add(new DfdElement(id, className, type, attributes));
                }
            }

            for (Map.Entry<String, String> entry : fileContentMap.entrySet()) {
                String sourceClass = entry.getKey();
                String sourceId = classNameToId.get(sourceClass);
                String content = entry.getValue();

                for (String targetClass : classNameToId.keySet()) {
                    if (!sourceClass.equals(targetClass) && content.contains(targetClass)) {
                        String targetId = classNameToId.get(targetClass);
                        String edgeId = sourceId + "->" + targetId;
                        boolean encrypted = content.contains("encrypted=\\\"true\\\"");
                        edges.add(new DfdEdge(edgeId, sourceId, targetId, "HTTP", encrypted));
                    }
                }
            }
        }

        return new DataFlowDiagram(elements, edges);
    }
}
