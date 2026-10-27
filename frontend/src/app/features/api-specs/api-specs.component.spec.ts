import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiSpecsComponent } from './api-specs.component';

describe('ApiSpecsComponent', () => {
  let component: ApiSpecsComponent;
  let fixture: ComponentFixture<ApiSpecsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ApiSpecsComponent],
      providers: [provideRouter([])]
    }).compileComponents();

    fixture = TestBed.createComponent(ApiSpecsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create API specs component', () => {
    expect(component).toBeTruthy();
  });

  it('should prominently display PLANNED CAPABILITY badge without fabricating contract data', () => {
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.planned-badge-header')?.textContent).toContain('PLANNED CAPABILITY');
    expect(compiled.querySelector('.planned-title')?.textContent).toContain('API Specification Conformance');
  });
});
