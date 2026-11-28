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
                "username": "admin",
                "password": "Password123!",
            },
        )
        assert r.status_code == 200, f"Auth failed: {r.text}"
        token = r.json()["access_token"]
        print("[1] Keycloak OIDC Authentication: SUCCESS (Admin Bearer JWT acquired)")

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

        # 8. Phase 8.1 Autonomous SOAR: Dynamic WAF Ban & Export
        waf_ban_r = await client.post(
            "http://localhost:8000/api/v1/security/soar/waf/ban",
            headers=headers,
            json={
                "ipOrCidr": "198.51.100.77",
                "reason": "Live audit autonomous threat mitigation test",
                "incidentId": "INC-AUDIT-WAF-01",
                "ttlHours": 1,
                "source": "SOAR"
            }
        )
        print(f"[8] POST /api/v1/security/soar/waf/ban: Status {waf_ban_r.status_code}")
        assert waf_ban_r.status_code == 201, "Dynamic WAF ban creation failed"
        waf_rule = waf_ban_r.json()
        waf_rule_id = waf_rule["id"]

        cf_export_r = await client.get("http://localhost:8000/api/v1/security/soar/waf/export/cloudflare", headers=headers)
        print(f"    Cloudflare WAF Export: Status {cf_export_r.status_code}, Items={len(cf_export_r.json().get('items', []))}")
        assert cf_export_r.status_code == 200

        aws_export_r = await client.get("http://localhost:8000/api/v1/security/soar/waf/export/aws", headers=headers)
        print(f"    AWS WAF Export: Status {aws_export_r.status_code}, Addrs={len(aws_export_r.json().get('Addresses', []))}")
        assert aws_export_r.status_code == 200

        # Cleanup test ban
        del_ban_r = await client.delete(f"http://localhost:8000/api/v1/security/soar/waf/ban/{waf_rule_id}", headers=headers)
        print(f"    DELETE /api/v1/security/soar/waf/ban/{waf_rule_id}: Status {del_ban_r.status_code}")
        assert del_ban_r.status_code == 204

        # 9. Phase 8.1 Autonomous SOAR: Distributed Token Revocation Ledger
        jti_test = f"jti-audit-{uuid.uuid4().hex[:8]}"
        revoke_r = await client.post(
            "http://localhost:8000/api/v1/security/soar/tokens/revoke",
            headers=headers,
            json={
                "jti": jti_test,
                "subject": "audit.test.user",
                "reason": "Live integration cryptographic revocation test",
                "ttlHours": 2
            }
        )
        print(f"[9] POST /api/v1/security/soar/tokens/revoke: Status {revoke_r.status_code}")
        assert revoke_r.status_code == 201, "Token revocation failed"

        revoked_list_r = await client.get("http://localhost:8000/api/v1/security/soar/tokens/revoked", headers=headers)
        print(f"    GET /api/v1/security/soar/tokens/revoked: Status {revoked_list_r.status_code}, Total={len(revoked_list_r.json())}")
        assert revoked_list_r.status_code == 200
        assert any(t["jti"] == jti_test for t in revoked_list_r.json())

        # 10. Phase 8.1 Autonomous SOAR: Ticketing & Webhook Sync
        ticket_r = await client.post(
            "http://localhost:8000/api/v1/security/soar/tickets",
            headers=headers,
            json={
                "incidentId": "INC-AUDIT-SOAR-99",
                "externalSystem": "JIRA",
                "title": "Live SOAR dispatch integration audit ticket",
                "severity": "CRITICAL",
                "assignee": "secops.lead"
            }
        )
        print(f"[10] POST /api/v1/security/soar/tickets: Status {ticket_r.status_code}")
        assert ticket_r.status_code == 201
        ticket_data = ticket_r.json()
        external_key = ticket_data["externalTicketId"]
        print(f"     Dispatched external ticket: {external_key} ({ticket_data['externalSystem']})")

        callback_r = await client.post(
            "http://localhost:8000/api/v1/security/soar/tickets/callback",
            json={
                "externalTicketId": external_key,
                "status": "IN_PROGRESS",
                "comment": "Automated callback verified in live audit"
            }
        )
        print(f"     POST /api/v1/security/soar/tickets/callback: Status {callback_r.status_code}")
        assert callback_r.status_code == 200
        assert callback_r.json()["status"] == "IN_PROGRESS"

        # 11. Phase 8.1 Autonomous SOAR: Adaptive Step-Up Challenge Gate
        chal_sess_id = f"session-chal-{uuid.uuid4().hex[:8]}"
        issue_chal_r = await client.post(
            "http://localhost:8000/api/v1/security/soar/challenge/issue",
            headers=headers,
            json={
                "sessionId": chal_sess_id,
                "reason": "Anomalous multi-resource exfiltration trajectory",
                "threatRisk": 0.84
            }
        )
        print(f"[11] POST /api/v1/security/soar/challenge/issue: Status {issue_chal_r.status_code}")
        assert issue_chal_r.status_code == 201
        chal_data = issue_chal_r.json()
        nonce = chal_data["challengeNonce"]
        print(f"     Challenge Nonce Issued: {nonce} (Risk: {chal_data['threatRisk']})")

        verify_chal_r = await client.post(
            "http://localhost:8000/api/v1/security/soar/challenge/verify",
            json={
                "sessionId": chal_sess_id,
                "responseToken": nonce
            }
        )
        print(f"     POST /api/v1/security/soar/challenge/verify: Status {verify_chal_r.status_code}")
        assert verify_chal_r.status_code == 200
        assert verify_chal_r.json()["verified"] is True
        print(f"     Challenge Cleared Status: {verify_chal_r.json()['status']}")

        metrics_r = await client.get("http://localhost:8000/api/v1/security/soar/challenge/metrics", headers=headers)
        print(f"     GET /api/v1/security/soar/challenge/metrics: Status {metrics_r.status_code}, ActiveClearances={metrics_r.json().get('activeClearances')}")
        assert metrics_r.status_code == 200

        # 12. Phase 8.2 AI Adversary & Self-Healing Policy Synthesizer
        camp_r = await client.post(
            "http://localhost:8000/api/v1/security/adversary/campaigns/run",
            headers=headers,
            json={
                "name": "Live Audit Beneficiary Probing Campaign",
                "targetEndpoint": "POST /api/v1/beneficiaries",
                "strategy": "STEP_SKIPPING",
                "probeCount": 10
            }
        )
        print(f"[12] POST /api/v1/security/adversary/campaigns/run: Status {camp_r.status_code}")
        assert camp_r.status_code == 201
        camp_data = camp_r.json()
        print(f"     Adversary Probes: Total={camp_data['totalProbes']}, Evaded={camp_data['evadedProbes']} ({camp_data['evasionRate']*100:.1f}%)")

        synth_r = await client.post(
            "http://localhost:8000/api/v1/security/adversary/synthesizer/synthesize",
            headers=headers,
            json={"campaignId": camp_data["id"]}
        )
        print(f"     POST /api/v1/security/adversary/synthesizer/synthesize: Status {synth_r.status_code}")
        assert synth_r.status_code == 201
        synth_data = synth_r.json()
        cand_id = synth_data["id"]
        print(f"     Candidate Policy Generated: [{cand_id}] Rule='{synth_data['ruleId']}'")

        eval_r = await client.post(
            f"http://localhost:8000/api/v1/security/adversary/synthesizer/evaluate/{cand_id}",
            headers=headers,
            json={"shadowBatchSize": 25}
        )
        print(f"     POST .../synthesizer/evaluate/{cand_id}: Status {eval_r.status_code}, FPR={eval_r.json().get('shadowFpr')}")
        assert eval_r.status_code == 200
        assert eval_r.json().get("shadowFpr") == 0.0

        promote_r = await client.post(
            f"http://localhost:8000/api/v1/security/adversary/synthesizer/promote/{cand_id}",
            headers=headers
        )
        print(f"     POST .../synthesizer/promote/{cand_id}: Status {promote_r.status_code}, Status={promote_r.json().get('status')}")
        assert promote_r.status_code == 200
        assert promote_r.json().get("status") == "PROMOTED"

        # Verify edge hot-load enforcement immediately blocks unauthenticated beneficiary creation
        fresh_beneficiary_sess = f"sess-beneficiary-{uuid.uuid4().hex[:8]}"
        verify_healed_r = await client.post(
            "http://localhost:8000/api/v1/security/workflow/verify",
            headers=headers,
            json={"sessionId": fresh_beneficiary_sess, "method": "POST", "path": "/api/v1/beneficiaries"}
        )
        print(f"     Edge Verification on Healed Target (/api/v1/beneficiaries): Status {verify_healed_r.status_code}, Allowed={verify_healed_r.json().get('allowed')}")
        assert verify_healed_r.json().get("allowed") is False, "Healed rule should block skipped beneficiary step"
        print(f"     Healed Rule ID: {verify_healed_r.json().get('ruleId')} (HOT-LOADED SUCCESSFULLY)")

    print("=" * 75)
    print("LIVE INTEGRATION & ENFORCEMENT AUDIT: 100% SUCCESS")
    print("=" * 75)

if __name__ == "__main__":
    asyncio.run(run_live_integration_audit())
