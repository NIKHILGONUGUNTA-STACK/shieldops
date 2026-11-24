import { TestBed } from '@angular/core/testing';
import { take } from 'rxjs';
import { SocWebSocketService } from './soc-websocket.service';
import { SocRealtimeNotification } from '../models/notification.model';

describe('SocWebSocketService', () => {
  let service: SocWebSocketService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [SocWebSocketService]
    });
    service = TestBed.inject(SocWebSocketService);
  });

  afterEach(() => {
    service.ngOnDestroy();
  });

  it('should be created and initialize connection status stream', (done) => {
    expect(service).toBeTruthy();
    service.connectionStatus$.pipe(take(1)).subscribe(status => {
      expect(['DISCONNECTED', 'CONNECTING', 'CONNECTED']).toContain(status);
      done();
    });
  });

  it('should transition to CONNECTED on receiving STOMP CONNECTED frame', () => {
    service.handleMessage('CONNECTED\nversion:1.2\n\n\0');

    let currentStatus = '';
    service.connectionStatus$.pipe(take(1)).subscribe(status => {
      currentStatus = status;
    });
    expect(currentStatus).toBe('CONNECTED');
  });

  it('should parse notification MESSAGE frame and emit to notifications$ and activeAlerts$', () => {
    const mockNotification: SocRealtimeNotification = {
      id: 'notif-101',
      type: 'INCIDENT_ALERT',
      title: 'BOLA Exploit Alert',
      message: 'Unauthorized access to customer account 2001',
      severity: 'CRITICAL',
      entityId: 'inc-2001',
      entityType: 'INCIDENT',
      timestamp: new Date().toISOString()
    };

    const stompFrame = `MESSAGE\ndestination:/topic/notifications\nsubscription:sub-0\n\n${JSON.stringify(mockNotification)}\0`;

    let receivedNotification: any = null;
    service.notifications$.pipe(take(1)).subscribe(notif => {
      receivedNotification = notif;
    });

    service.handleMessage(stompFrame);

    expect(receivedNotification).not.toBeNull();
    expect(receivedNotification?.id).toBe('notif-101');
    expect(receivedNotification?.severity).toBe('CRITICAL');

    let currentAlerts: SocRealtimeNotification[] = [];
    service.activeAlerts$.pipe(take(1)).subscribe(alerts => {
      currentAlerts = alerts;
    });
    expect(currentAlerts.length).toBeGreaterThan(0);
    expect(currentAlerts[0].id).toBe('notif-101');
  });

  it('should dismiss an alert by ID', () => {
    const mockNotification: SocRealtimeNotification = {
      id: 'notif-102',
      type: 'SYSTEM_HEALTH',
      title: 'Health Check',
      message: 'Broker Active',
      severity: 'INFO',
      entityId: 'sys-1',
      entityType: 'SYSTEM',
      timestamp: new Date().toISOString()
    };

    service.handleMessage(`MESSAGE\ndestination:/topic/notifications\n\n${JSON.stringify(mockNotification)}\0`);

    let currentAlerts: SocRealtimeNotification[] = [];
    service.activeAlerts$.pipe(take(1)).subscribe(alerts => currentAlerts = alerts);
    expect(currentAlerts.some(a => a.id === 'notif-102')).toBeTrue();

    service.dismissAlert('notif-102');

    service.activeAlerts$.pipe(take(1)).subscribe(alerts => currentAlerts = alerts);
    expect(currentAlerts.some(a => a.id === 'notif-102')).toBeFalse();
  });

  it('should clear all active alerts', () => {
    const mockNotification: SocRealtimeNotification = {
      id: 'notif-103',
      type: 'BURST_INGESTION',
      title: 'Traffic Burst',
      message: '50 events generated',
      severity: 'LOW',
      entityId: 'sim-1',
      entityType: 'SIMULATION',
      timestamp: new Date().toISOString()
    };

    service.handleMessage(`MESSAGE\ndestination:/topic/notifications\n\n${JSON.stringify(mockNotification)}\0`);
    service.clearAllAlerts();

    let currentAlerts: SocRealtimeNotification[] = [];
    service.activeAlerts$.pipe(take(1)).subscribe(alerts => currentAlerts = alerts);
    expect(currentAlerts.length).toBe(0);
  });
});
