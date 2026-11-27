import asyncio
import uuid
import httpx

async def run_live_integration_audit():
    print("=" * 75)
    print("AEGIS LIVE CLUSTER INTEGRATION & BEHAVIORAL ENFORCEMENT AUDIT")
    print("=" * 75)

    async with httpx.AsyncClient(timeout=10) as client:
        # 1. Keycloak Authentication
        r = await client.post(
            "http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "aegis-local",
                "username": "analyst",
                "password": "Password123!",
            },
        )
        assert r.status_code == 200, f"Auth failed: {r.text}"
        token = r.json()["access_token"]
        print("[1] Keycloak OIDC Authentication: SUCCESS (Bearer JWT acquired)")

        headers = {"Authorization": f"Bearer {token}", "X-Tenant-Id": "tenant-fintech-us"}

        # 2. Query Workflow Rules on Gateway
        rules_r = await client.get("http://localhost:8000/api/v1/security/workflow/rules", headers=headers)
        print(f"[2] GET /api/v1/security/workflow/rules: Status {rules_r.status_code}")
        for rule in rules_r.json():
            print(f"    - [{rule.get('id')}] {rule.get('targetMethod')} {rule.get('targetPathPattern')}")
            print(f"      Description: {rule.get('description')}")
            print(f"      Required Predecessors: {rule.get('requiredPredecessors')}")

        # 3. Test Edge Verification API with UNSATISFIED Prerequisites on a Fresh Session
        fresh_session_id = f"session-audit-{uuid.uuid4().hex[:8]}"
        verify_r1 = await client.post(
            "http://localhost:8000/api/v1/security/workflow/verify",
            headers=headers,
            json={"sessionId": fresh_session_id, "method": "POST", "path": "/api/v1/transfers"},
        )
        print(f"[3] Edge Verification Before Prerequisite (Fresh Session: {fresh_session_id}): Status {verify_r1.status_code}")
        res1 = verify_r1.json()
        print(f"    Allowed: {res1.get('allowed')} (Expected: False - BLOCKED)")
        print(f"    Enforced Rule: {res1.get('ruleId')}")
        print(f"    Reason: {res1.get('reason')}")
        print(f"    Missing Predecessors: {res1.get('missingPrerequisites')}")
        assert res1.get("allowed") is False, "Workflow should have BLOCKED skipped-step transfer"

        # 4. Client Executes Prerequisite request through Gateway to record state in Redis
        prereq_r = await client.get(
            "http://localhost:8000/api/v1/accounts",
            headers={**headers, "X-Session-Id": fresh_session_id},
        )
        print(f"[4] Client Executes Prerequisite (GET /api/v1/accounts): Status {prereq_r.status_code}")
        assert prereq_r.status_code == 200, "Prerequisite request through Gateway failed"

        # 5. Verify that Redis session state tracked the executed step
        session_r = await client.get(
            f"http://localhost:8000/api/v1/security/workflow/sessions/{fresh_session_id}",
            headers=headers,
        )
        print(f"[5] Redis In-Memory Session Steps: Status {session_r.status_code}, Steps: {session_r.json()}")
        assert "GET /api/v1/accounts" in session_r.json(), "Prerequisite step was not recorded in Redis session"

        # 6. Re-evaluate Workflow Verification after prerequisite is satisfied
        verify_r2 = await client.post(
            "http://localhost:8000/api/v1/security/workflow/verify",
            headers=headers,
            json={"sessionId": fresh_session_id, "method": "POST", "path": "/api/v1/transfers"},
        )
        print(f"[6] Edge Verification After Prerequisite: Status {verify_r2.status_code}")
        res2 = verify_r2.json()
        print(f"    Allowed: {res2.get('allowed')} (Expected: True - PERMITTED)")
        print(f"    Completed Steps: {res2.get('completedSteps')}")
        assert res2.get("allowed") is True, "Workflow should have ALLOWED transfer after prerequisite satisfied"

        # 7. Query Outlier Stats from Streaming Scorer
        stats_r = await client.get("http://localhost:8000/api/v1/security/workflow/outliers/stats", headers=headers)
        print(f"[7] GET /api/v1/security/workflow/outliers/stats: Status {stats_r.status_code}")
        stats = stats_r.json()
        print(f"    Total Tracked Endpoints: {len(stats)}")
        for ep in list(stats.keys())[:4]:
            ep_data = stats[ep]
            payload_info = ep_data.get("payload", {})
            latency_info = ep_data.get("latency", {})
            print(f"    - Endpoint {ep}:")
            print(f"        Payload: samples={payload_info.get('count', 0)}, mean={payload_info.get('mean', 0.0):.1f}B")
            print(f"        Latency: samples={latency_info.get('count', 0)}, mean={latency_info.get('mean', 0.0):.2f}ms")

    print("=" * 75)
    print("LIVE INTEGRATION & ENFORCEMENT AUDIT: 100% SUCCESS")
    print("=" * 75)

if __name__ == "__main__":
    asyncio.run(run_live_integration_audit())
