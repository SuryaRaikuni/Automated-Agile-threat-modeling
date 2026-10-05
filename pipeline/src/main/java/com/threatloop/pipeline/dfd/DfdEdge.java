package com.threatloop.pipeline.dfd;

public record DfdEdge(String id, String sourceId, String targetId, String protocol, boolean encrypted) {}
