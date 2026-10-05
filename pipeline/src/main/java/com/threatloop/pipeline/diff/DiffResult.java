package com.threatloop.pipeline.diff;
import com.threatloop.pipeline.model.Threat;
import java.util.List;

public record DiffResult(List<Threat> newThreats, List<Threat> changedThreats, List<Threat> resolvedThreats) {}
