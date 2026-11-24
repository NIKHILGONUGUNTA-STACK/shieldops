import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { WebhookService } from './webhook.service';
import { WebhookSubscription, WebhookSubscriptionCreateRequest, WebhookDispatchResult } from '../models/webhook.model';

describe('WebhookService', () => {
  let service: WebhookService;
  let httpMock: HttpTestingController;

  const mockSub: WebhookSubscription = {
    id: 'sub-slack-123',
    tenantId: 'tenant-fintech-us',
    name: 'SOC Alerts Slack',
    targetUrl: 'https://hooks.slack.com/services/T00/B00/test',
    eventTypes: ['INCIDENT_CRITICAL'],
    enabled: true,
    createdAt: '2026-11-20T00:00:00Z',
    successCount: 10,
    failureCount: 0
  };

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [WebhookService]
    });
    service = TestBed.inject(WebhookService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should retrieve webhook subscriptions', () => {
    service.getSubscriptions('tenant-fintech-us').subscribe(subs => {
      expect(subs.length).toBe(1);
      expect(subs[0].name).toBe('SOC Alerts Slack');
    });

    const req = httpMock.expectOne('/api/v1/admin/webhooks?tenantId=tenant-fintech-us');
    expect(req.request.method).toBe('GET');
    req.flush([mockSub]);
  });

  it('should create and delete webhook subscriptions', () => {
    const createReq: WebhookSubscriptionCreateRequest = {
      tenantId: 'tenant-fintech-us',
      name: 'PagerDuty Integration',
      targetUrl: 'https://events.pagerduty.com/v2/enqueue',
      eventTypes: ['INCIDENT_CRITICAL', 'CAMPAIGN_ESCALATED']
    };

    service.createSubscription(createReq).subscribe(sub => {
      expect(sub.id).toBe('sub-pd-456');
    });

    const req1 = httpMock.expectOne('/api/v1/admin/webhooks');
    expect(req1.request.method).toBe('POST');
    req1.flush({ ...mockSub, id: 'sub-pd-456', name: 'PagerDuty Integration' });

    service.deleteSubscription('sub-pd-456').subscribe();
    const req2 = httpMock.expectOne('/api/v1/admin/webhooks/sub-pd-456');
    expect(req2.request.method).toBe('DELETE');
    req2.flush(null);
  });

  it('should trigger test ping to existing subscription', () => {
    const mockResult: WebhookDispatchResult = {
      subscriptionId: 'sub-slack-123',
      targetUrl: 'https://hooks.slack.com/services/T00/B00/test',
      statusCode: 200,
      success: true,
      message: 'Delivered successfully',
      latencyMs: 145,
      timestamp: '2026-11-24T12:00:00Z'
    };

    service.triggerTest('sub-slack-123').subscribe(result => {
      expect(result.success).toBeTrue();
      expect(result.statusCode).toBe(200);
    });

    const req = httpMock.expectOne('/api/v1/admin/webhooks/sub-slack-123/test');
    expect(req.request.method).toBe('POST');
    req.flush(mockResult);
  });
});
