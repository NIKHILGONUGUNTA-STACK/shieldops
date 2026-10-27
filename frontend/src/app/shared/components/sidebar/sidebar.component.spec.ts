import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { SidebarComponent } from './sidebar.component';
import { LayoutService } from '../../../core/services/layout.service';

describe('SidebarComponent', () => {
  let component: SidebarComponent;
  let fixture: ComponentFixture<SidebarComponent>;
  let layoutService: LayoutService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SidebarComponent],
      providers: [provideRouter([]), LayoutService]
    }).compileComponents();

    fixture = TestBed.createComponent(SidebarComponent);
    component = fixture.componentInstance;
    layoutService = TestBed.inject(LayoutService);
    fixture.detectChanges();
  });

  it('should create the sidebar component', () => {
    expect(component).toBeTruthy();
  });

  it('should render all 5 grouped navigation sections', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const sectionTitles = Array.from(compiled.querySelectorAll('.nav-section-title')).map(el => el.textContent?.trim());
    expect(sectionTitles).toContain('DASHBOARD');
    expect(sectionTitles).toContain('ATTACKS & INVESTIGATION');
    expect(sectionTitles).toContain('API SECURITY');
    expect(sectionTitles).toContain('DETECTION & RESPONSE');
    expect(sectionTitles).toContain('GOVERNANCE & OPERATIONS');
  });

  it('should render 15 navigation links', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const navLinks = compiled.querySelectorAll('.nav-item');
    expect(navLinks.length).toBe(15);
  });

  it('should display PLANNED badges for API Inventory and API Specifications', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    const badges = Array.from(compiled.querySelectorAll('.badge-planned')).map(b => b.textContent?.trim());
    expect(badges.length).toBe(2);
    expect(badges.every(b => b === 'PLANNED')).toBeTrue();
  });

  it('should toggle collapsed state when collapse button is clicked', () => {
    expect(layoutService.isSidebarCollapsed()).toBeFalse();
    const compiled = fixture.nativeElement as HTMLElement;
    const collapseBtn = compiled.querySelector('.collapse-btn') as HTMLButtonElement;
    expect(collapseBtn).toBeTruthy();

    collapseBtn.click();
    fixture.detectChanges();
    expect(layoutService.isSidebarCollapsed()).toBeTrue();
    expect(compiled.querySelector('.soc-sidebar')?.classList.contains('collapsed')).toBeTrue();
  });

  it('should display ADVISORY MODE indicator in footer', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.advisory-pill')?.textContent).toContain('ADVISORY MODE');
    expect(compiled.querySelector('.stack-tag')?.textContent).toContain('SHIELDOPS v5.5');
  });
});
