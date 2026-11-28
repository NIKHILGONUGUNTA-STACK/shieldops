import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { FederationCenterComponent } from './federation-center.component';
import { SecurityApiService } from '../../core/services/security-api.service';
import {
  FederationNode,
  FederatedPolicyPayload,
  ConsensusVerificationResult
} from '../../core/models/security.models';

describe('FederationCenterComponent', () => {
  let component: FederationCenterComponent;
  let fixture: ComponentFixture<FederationCenterComponent>;
  let mockSecurityApi: jasmine.SpyObj<SecurityApiService>;

  function getInitialNodes(): FederationNode[] {
    return [
      {
        nodeId: 'node-us-east-primary',
        region: 'us-east-1',
        status: 'HEALTHY',
        endpointUrl: 'https://gateway-us-east.internal/api/v1',
        lastHeartbeat: new Date().toISOString(),
        latencyMs: 15,
        epoch: 100,
        stateMerkleRoot: 'a4f9b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8',
        vectorClock: { 'node-us-east-primary': 100 }
      },
      {
        nodeId: 'node-eu-central-dr',
        region: 'eu-central-1',
        status: 'HEALTHY',
        endpointUrl: 'https://gateway-eu-central.internal/api/v1',
        lastHeartbeat: new Date().toISOString(),
        latencyMs: 65,
        epoch: 100,
        stateMerkleRoot: 'a4f9b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8',
        vectorClock: { 'node-eu-central-dr': 100 }
      },
      {
        nodeId: 'node-ap-south-edge',
        region: 'ap-south-1',
        status: 'DEGRADED',
        endpointUrl: 'https://gateway-ap-south.internal/api/v1',
        lastHeartbeat: new Date().toISOString(),
        latencyMs: 130,
        epoch: 98,
        stateMerkleRoot: '0000000000000000000000000000000000000000000000000000000000000000',
        vectorClock: { 'node-ap-south-edge': 98 }
      }
    ];
  }

  const initialPolicies: FederatedPolicyPayload[] = [
    {
      policyId: 'FED-POL-001',
      policyType: 'WAF_IP_BAN',
      action: 'UPSERT',
      originNodeId: 'node-us-east-primary',
      originEpoch: 100,
      vectorClock: { 'node-us-east-primary': 100 },
      payloadJson: '{"ip":"198.51.100.24"}',
      cryptographicSignature: 'sig-001',
      timestamp: new Date().toISOString()
    },
    {
      policyId: 'FED-POL-002',
      policyType: 'TOKEN_REVOCATION',
      action: 'UPSERT',
      originNodeId: 'node-eu-central-dr',
      originEpoch: 100,
      vectorClock: { 'node-eu-central-dr': 100 },
      payloadJson: '{"jti":"token-compromised"}',
      cryptographicSignature: 'sig-002',
      timestamp: new Date().toISOString()
    }
  ];

  const initialConsensus: ConsensusVerificationResult = {
    synchronizedStatus: false,
    totalNodes: 3,
    healthyNodeCount: 2,
    divergentNodeCount: 1,
    globalMerkleRoot: 'a4f9b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8',
    nodeStates: {
      'node-us-east-primary': 'a4f9b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8',
      'node-eu-central-dr': 'a4f9b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8',
      'node-ap-south-edge': '0000000000000000000000000000000000000000000000000000000000000000'
    },
    totalPolicies: 2,
    conflictCount: 0,
    lastConsensusTime: new Date().toISOString()
  };

  beforeEach(async () => {
    mockSecurityApi = jasmine.createSpyObj('SecurityApiService', [
      'getFederationNodes',
      'getFederationConsensus',
      'reconcileFederationCluster',
      'getFederatedPolicies',
      'broadcastFederatedPolicy'
    ]);

    mockSecurityApi.getFederationNodes.and.callFake(() => of(getInitialNodes()));
    mockSecurityApi.getFederationConsensus.and.callFake(() => of({ ...initialConsensus }));
    mockSecurityApi.getFederatedPolicies.and.callFake(() => of([...initialPolicies]));

    await TestBed.configureTestingModule({
      imports: [FederationCenterComponent],
      providers: [
        { provide: SecurityApiService, useValue: mockSecurityApi }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(FederationCenterComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create component and load federation nodes and consensus state', () => {
    expect(component).toBeTruthy();
    expect(component.nodes.length).toBe(3);
    expect(component.policies.length).toBe(2);
    expect(component.consensus).toBeDefined();
    expect(component.consensus?.synchronizedStatus).toBeFalse();
  });

  it('should accurately compute healthy nodes count and average latency', () => {
    expect(component.healthyNodeCount).toBe(2);
    // (15 + 65 + 130) / 3 = 70 ms
    expect(component.averageLatencyMs).toBe(70);
  });

  it('should filter policies based on policy type selection', () => {
    component.setFilter('WAF_IP_BAN');
    expect(component.filteredPolicies.length).toBe(1);
    expect(component.filteredPolicies[0].policyType).toBe('WAF_IP_BAN');

    component.setFilter('TOKEN_REVOCATION');
    expect(component.filteredPolicies.length).toBe(1);
    expect(component.filteredPolicies[0].policyType).toBe('TOKEN_REVOCATION');

    component.setFilter('WORKFLOW_RULE');
    expect(component.filteredPolicies.length).toBe(0);

    component.setFilter('ALL');
    expect(component.filteredPolicies.length).toBe(2);
  });

  it('should trigger cluster reconciliation and update consensus to synchronized', () => {
    const reconciledConsensus: ConsensusVerificationResult = {
      ...initialConsensus,
      synchronizedStatus: true,
      healthyNodeCount: 3,
      divergentNodeCount: 0
    };
    mockSecurityApi.reconcileFederationCluster.and.returnValue(of(reconciledConsensus));

    component.reconcileCluster();

    expect(mockSecurityApi.reconcileFederationCluster).toHaveBeenCalled();
    expect(component.consensus?.synchronizedStatus).toBeTrue();
    expect(component.consensus?.divergentNodeCount).toBe(0);
  });

  it('should broadcast cross-region federated policy and refresh policy list', () => {
    const newPolicy: FederatedPolicyPayload = {
      policyId: 'FED-POL-BROADCAST-99',
      policyType: 'WAF_IP_BAN',
      action: 'UPSERT',
      originNodeId: 'node-us-east-primary',
      originEpoch: 101,
      vectorClock: { 'node-us-east-primary': 101 },
      payloadJson: '{"ip":"203.0.113.88"}',
      cryptographicSignature: 'sig-99',
      timestamp: new Date().toISOString()
    };
    mockSecurityApi.broadcastFederatedPolicy.and.returnValue(of(newPolicy));

    component.broadcastPolicy();

    expect(mockSecurityApi.broadcastFederatedPolicy).toHaveBeenCalled();
    expect(component.policies[0].policyId).toBe('FED-POL-BROADCAST-99');
    expect(component.openBroadcastModal).toBeFalse();
  });

  it('should format and truncate hash strings for UI presentation', () => {
    expect(component.truncateHash()).toBe('—');
    expect(component.truncateHash('short')).toBe('short');
    expect(component.truncateHash('a4f9b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8'))
      .toBe('a4f9b2c0...d5e6f7a8');
  });
});
