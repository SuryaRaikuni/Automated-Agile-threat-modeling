package com.threatloop.pipeline.report;
public record RunRecord(String runId, String sha, String branch, String timestamp, long durationMs, int newThreatCount, String status) {}
