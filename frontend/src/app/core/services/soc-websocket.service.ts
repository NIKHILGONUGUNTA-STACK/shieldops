import { Injectable, OnDestroy } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';
import { SocRealtimeNotification, WebSocketConnectionStatus } from '../models/notification.model';

/**
 * High-performance native WebSocket client with lightweight STOMP framing
 * for real-time SOC security streaming and instantaneous threat notifications.
 */
@Injectable({
  providedIn: 'root'
})
export class SocWebSocketService implements OnDestroy {
  private socket: WebSocket | null = null;
  private reconnectTimer: any = null;
  private isDestroyed = false;

  private connectionStatusSubject = new BehaviorSubject<WebSocketConnectionStatus>('DISCONNECTED');
  public connectionStatus$ = this.connectionStatusSubject.asObservable();

  private notificationsSubject = new Subject<SocRealtimeNotification>();
  public notifications$ = this.notificationsSubject.asObservable();

  private activeAlertsSubject = new BehaviorSubject<SocRealtimeNotification[]>([]);
  public activeAlerts$ = this.activeAlertsSubject.asObservable();

  private telemetrySubject = new Subject<any>();
  public telemetry$ = this.telemetrySubject.asObservable();

  private incidentsSubject = new Subject<any>();
  public incidents$ = this.incidentsSubject.asObservable();

  constructor() {
    this.connect();
  }

  public connect(): void {
    if (this.isDestroyed || (this.socket && this.socket.readyState === WebSocket.OPEN)) {
      return;
    }

    // Guard against attempting WebSocket handshake against Karma test runner server
    if (typeof (window as any).__karma__ !== 'undefined' || window.location.port === '9876') {
      return;
    }

    this.connectionStatusSubject.next('CONNECTING');

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.port === '4200' ? 'localhost:8000' : window.location.host;
    const wsUrl = `${protocol}//${host}/ws/soc-feed-raw`;

    try {
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        this.sendStompConnect();
      };

      this.socket.onmessage = (event) => {
        this.handleMessage(event.data);
      };

      this.socket.onerror = () => {
        this.connectionStatusSubject.next('DISCONNECTED');
      };

      this.socket.onclose = () => {
        this.connectionStatusSubject.next('DISCONNECTED');
        this.scheduleReconnect();
      };
    } catch {
      this.connectionStatusSubject.next('DISCONNECTED');
      this.scheduleReconnect();
    }
  }

  private sendStompConnect(): void {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
    const connectFrame = 'CONNECT\naccept-version:1.2,1.1,1.0\nheart-beat:10000,10000\n\n\0';
    this.socket.send(connectFrame);
  }

  private subscribeToTopics(): void {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;

    const topics = [
      '/topic/notifications',
      '/topic/incidents',
      '/topic/telemetry',
      '/topic/campaigns'
    ];

    topics.forEach((topic, idx) => {
      const subFrame = `SUBSCRIBE\nid:sub-${idx}\ndestination:${topic}\n\n\0`;
      this.socket?.send(subFrame);
    });
  }

  public handleMessage(data: string): void {
    if (!data) return;

    if (data.startsWith('CONNECTED')) {
      this.connectionStatusSubject.next('CONNECTED');
      this.subscribeToTopics();
      return;
    }

    if (data.startsWith('MESSAGE')) {
      const bodyIndex = data.indexOf('\n\n');
      if (bodyIndex !== -1) {
        const headerPart = data.substring(0, bodyIndex);
        const rawBody = data.substring(bodyIndex + 2).replace(/\0$/, '').trim();

        if (headerPart.includes('destination:/topic/notifications')) {
          try {
            const notification: SocRealtimeNotification = JSON.parse(rawBody);
            this.notificationsSubject.next(notification);
            const current = this.activeAlertsSubject.getValue();
            this.activeAlertsSubject.next([notification, ...current.slice(0, 49)]);
          } catch {
            // malformed json safe ignore
          }
        } else if (headerPart.includes('destination:/topic/telemetry')) {
          try {
            this.telemetrySubject.next(JSON.parse(rawBody));
          } catch {
            // ignore
          }
        } else if (headerPart.includes('destination:/topic/incidents')) {
          try {
            this.incidentsSubject.next(JSON.parse(rawBody));
          } catch {
            // ignore
          }
        }
      }
    }
  }

  public dismissAlert(id: string): void {
    const current = this.activeAlertsSubject.getValue();
    this.activeAlertsSubject.next(current.filter(a => a.id !== id));
  }

  public clearAllAlerts(): void {
    this.activeAlertsSubject.next([]);
  }

  private scheduleReconnect(): void {
    if (this.isDestroyed || this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 5000);
  }

  ngOnDestroy(): void {
    this.isDestroyed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
  }
}
