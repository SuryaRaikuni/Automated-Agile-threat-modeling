package com.threatloop.pipeline.dfd;
import java.util.Map;

public record DfdElement(String id, String name, ElementType type, Map<String, String> attributes) {
    public boolean hasAttribute(String key) {
        return attributes != null && attributes.containsKey(key);
    }
    
    public String getAttribute(String key, String defaultValue) {
        return hasAttribute(key) ? attributes.get(key) : defaultValue;
    }
}
