import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { DetectionRulesComponent } from './detection-rules.component';
import { SecurityApiService } from '../../core/services/security-api.service';

describe('DetectionRulesComponent', () => {
  let component: DetectionRulesComponent;
  let fixture: ComponentFixture<DetectionRulesComponent>;
  let apiServiceSpy: jasmine.SpyObj<SecurityApiService>;

  beforeEach(async () => {
    apiServiceSpy = jasmine.createSpyObj('SecurityApiService', ['getOverview']);
    apiServiceSpy.getOverview.and.returnValue(of({
      totalEvents24h: 500,
      totalAnomalies24h: 30,
      activeIncidentsCount: 5,
      incidentsBySeverity: {},
      incidentsByCategory: {},
      recentIncidents: [],
      topRulesTriggered: [
        { ruleId: 'RULE-BOLA-01', count: 15 },
        { ruleId: 'RULE-AUTH-01', count: 8 }
      ],
      eventVolumeTrend: []
    }));

    await TestBed.configureTestingModule({
      imports: [DetectionRulesComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityApiService, useValue: apiServiceSpy }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(DetectionRulesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create detection rules component and render 6 rules', () => {
    expect(component).toBeTruthy();
    expect(component.rules.length).toBe(6);
    const compiled = fixture.nativeElement as HTMLElement;
    const ruleCards = compiled.querySelectorAll('.rule-card');
    expect(ruleCards.length).toBe(6);
  });

  it('should display live trigger stats from overview API', () => {
    expect(component.getTriggerCount('RULE-BOLA-01')).toBe(15);
    expect(component.getTriggerCount('RULE-AUTH-01')).toBe(8);
    expect(component.getTriggerCount('RULE-INJ-01')).toBe(0);
  });
});
