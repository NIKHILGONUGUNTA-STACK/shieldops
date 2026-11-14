package com.aegis.gateway.detection.policy.dto;

import jakarta.validation.constraints.Size;

public record PolicyApprovalRequest(
    @Size(max = 1024) String comment
) {}
