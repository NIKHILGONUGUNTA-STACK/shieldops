import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiInventoryComponent } from './api-inventory.component';

describe('ApiInventoryComponent', () => {
  let component: ApiInventoryComponent;
  let fixture: ComponentFixture<ApiInventoryComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ApiInventoryComponent],
      providers: [provideRouter([])]
    }).compileComponents();

    fixture = TestBed.createComponent(ApiInventoryComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create API inventory component', () => {
    expect(component).toBeTruthy();
  });

  it('should prominently display PLANNED CAPABILITY badge without fabricating operational data', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.planned-badge-header')?.textContent).toContain('PLANNED CAPABILITY');
    expect(compiled.querySelector('.planned-badge-header')?.textContent).toContain('Phase 6 Roadmap');
    expect(compiled.querySelector('.planned-title')?.textContent).toContain('Automated API Inventory');
  });
});
