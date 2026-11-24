import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
  Tenant,
  TenantPageResponse,
  TenantCreateRequest,
  TenantStatusUpdateRequest,
  TenantQuotaUpdateRequest,
  TenantUsageResponse
} from '../models/tenant.model';

@Injectable({
  providedIn: 'root'
})
export class TenantService {
  private readonly baseUrl = '';

  constructor(private http: HttpClient) {}

  getTenants(params?: {
    page?: number;
    size?: number;
    tier?: string;
    status?: string;
    search?: string;
  }): Observable<TenantPageResponse> {
    let httpParams = new HttpParams();
    if (params) {
      if (params.page !== undefined) httpParams = httpParams.set('page', params.page.toString());
      if (params.size !== undefined) httpParams = httpParams.set('size', params.size.toString());
      if (params.tier) httpParams = httpParams.set('tier', params.tier);
      if (params.status) httpParams = httpParams.set('status', params.status);
      if (params.search) httpParams = httpParams.set('search', params.search);
    }
    return this.http.get<TenantPageResponse>(`${this.baseUrl}/api/v1/admin/tenants`, { params: httpParams });
  }

  getTenant(id: string): Observable<Tenant> {
    return this.http.get<Tenant>(`${this.baseUrl}/api/v1/admin/tenants/${encodeURIComponent(id)}`);
  }

  createTenant(req: TenantCreateRequest): Observable<Tenant> {
    return this.http.post<Tenant>(`${this.baseUrl}/api/v1/admin/tenants`, req);
  }

  updateStatus(id: string, req: TenantStatusUpdateRequest): Observable<Tenant> {
    return this.http.patch<Tenant>(`${this.baseUrl}/api/v1/admin/tenants/${encodeURIComponent(id)}/status`, req);
  }

  updateQuotas(id: string, req: TenantQuotaUpdateRequest): Observable<Tenant> {
    return this.http.put<Tenant>(`${this.baseUrl}/api/v1/admin/tenants/${encodeURIComponent(id)}/quotas`, req);
  }

  getTenantUsage(id: string): Observable<TenantUsageResponse> {
    return this.http.get<TenantUsageResponse>(`${this.baseUrl}/api/v1/admin/tenants/${encodeURIComponent(id)}/usage`);
  }
}
