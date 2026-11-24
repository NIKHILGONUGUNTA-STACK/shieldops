import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  WebhookSubscription,
  WebhookSubscriptionCreateRequest,
  WebhookTestDispatchRequest,
  WebhookDispatchResult
} from '../models/webhook.model';

@Injectable({
  providedIn: 'root'
})
export class WebhookService {
  private readonly baseUrl = '';

  constructor(private http: HttpClient) {}

  getSubscriptions(tenantId?: string): Observable<WebhookSubscription[]> {
    let params = new HttpParams();
    if (tenantId) {
      params = params.set('tenantId', tenantId);
    }
    return this.http.get<WebhookSubscription[]>(`${this.baseUrl}/api/v1/admin/webhooks`, { params });
  }

  getSubscription(id: string): Observable<WebhookSubscription> {
    return this.http.get<WebhookSubscription>(`${this.baseUrl}/api/v1/admin/webhooks/${encodeURIComponent(id)}`);
  }

  createSubscription(req: WebhookSubscriptionCreateRequest): Observable<WebhookSubscription> {
    return this.http.post<WebhookSubscription>(`${this.baseUrl}/api/v1/admin/webhooks`, req);
  }

  deleteSubscription(id: string): Observable<void> {
    return this.http.delete<void>(`${this.baseUrl}/api/v1/admin/webhooks/${encodeURIComponent(id)}`);
  }

  triggerTest(id: string): Observable<WebhookDispatchResult> {
    return this.http.post<WebhookDispatchResult>(`${this.baseUrl}/api/v1/admin/webhooks/${encodeURIComponent(id)}/test`, {});
  }

  testDispatch(req: WebhookTestDispatchRequest): Observable<WebhookDispatchResult> {
    return this.http.post<WebhookDispatchResult>(`${this.baseUrl}/api/v1/admin/webhooks/test-dispatch`, req);
  }
}
