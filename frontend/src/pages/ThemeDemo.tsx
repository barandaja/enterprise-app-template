import React from 'react';
import { MainLayout } from '../layouts/MainLayout';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/Card';
import { ThemeToggle, ThemeIcon, useThemeToggle } from '../components/ThemeToggle';
import { Alert } from '../components/Alert';
import { Badge } from '../components/Badge';
import type { PageProps, BreadcrumbItem } from '../types';

const breadcrumbs: BreadcrumbItem[] = [
  { label: 'Home', href: '/' },
  { label: 'Theme Demo' },
];

interface DemoSectionProps {
  title: string;
  description: string;
  children: React.ReactNode;
}

function DemoSection({ title, description, children }: DemoSectionProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap items-center gap-4">
          {children}
        </div>
      </CardContent>
    </Card>
  );
}

function ThemeDemo({ className }: PageProps) {
  const { theme, resolvedTheme, isLight, isDark, isSystem } = useThemeToggle();
  
  return (
    <MainLayout breadcrumbs={breadcrumbs} className={className}>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-2">Theme Toggle Demo</h1>
          <p className="text-muted-foreground">
            Explore different theme toggle variants and configurations
          </p>
        </div>

        {/* Current Theme Status */}
        <Alert variant="info">
          <div className="flex items-center space-x-2">
            <ThemeIcon size="md" />
            <div>
              <h4 className="font-semibold">Current Theme Status</h4>
              <div className="flex flex-wrap items-center gap-2 mt-1">
                <Badge variant={theme === 'light' ? 'default' : 'secondary'}>
                  Theme: {theme}
                </Badge>
                <Badge variant={resolvedTheme === 'light' ? 'default' : 'secondary'}>
                  Resolved: {resolvedTheme}
                </Badge>
                <Badge variant={isLight ? 'default' : 'secondary'}>
                  Light: {isLight ? 'Yes' : 'No'}
                </Badge>
                <Badge variant={isDark ? 'default' : 'secondary'}>
                  Dark: {isDark ? 'Yes' : 'No'}
                </Badge>
                <Badge variant={isSystem ? 'default' : 'secondary'}>
                  System: {isSystem ? 'Yes' : 'No'}
                </Badge>
              </div>
            </div>
          </div>
        </Alert>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Compact Layout */}
          <DemoSection
            title="Compact Layout"
            description="Minimal toggle button that cycles through themes on click"
          >
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium w-16">Small:</span>
                <ThemeToggle layout="compact" size="sm" />
                <ThemeToggle layout="compact" size="sm" variant="subtle" />
                <ThemeToggle layout="compact" size="sm" variant="outline" />
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium w-16">Medium:</span>
                <ThemeToggle layout="compact" size="md" />
                <ThemeToggle layout="compact" size="md" variant="subtle" />
                <ThemeToggle layout="compact" size="md" variant="outline" />
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium w-16">Large:</span>
                <ThemeToggle layout="compact" size="lg" />
                <ThemeToggle layout="compact" size="lg" variant="subtle" />
                <ThemeToggle layout="compact" size="lg" variant="outline" />
              </div>
            </div>
          </DemoSection>

          {/* Button Group Layout */}
          <DemoSection
            title="Button Group Layout"
            description="Button group with individual theme options"
          >
            <div className="space-y-4 w-full">
              <div>
                <span className="text-sm font-medium block mb-2">Without labels:</span>
                <ThemeToggle layout="buttons" showLabels={false} includeSystem />
              </div>
              <div>
                <span className="text-sm font-medium block mb-2">With labels:</span>
                <ThemeToggle layout="buttons" showLabels includeSystem />
              </div>
              <div>
                <span className="text-sm font-medium block mb-2">Without system option:</span>
                <ThemeToggle layout="buttons" showLabels includeSystem={false} />
              </div>
            </div>
          </DemoSection>

          {/* Dropdown Layout */}
          <DemoSection
            title="Dropdown Layout"
            description="Dropdown menu with theme descriptions"
          >
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium">With system:</span>
                <ThemeToggle layout="dropdown" includeSystem />
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium">Without system:</span>
                <ThemeToggle layout="dropdown" includeSystem={false} />
              </div>
            </div>
          </DemoSection>

          {/* Size Variants */}
          <DemoSection
            title="Size Variants"
            description="Different sizes for various use cases"
          >
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium">Small:</span>
                <ThemeToggle layout="buttons" showLabels size="sm" />
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium">Medium:</span>
                <ThemeToggle layout="buttons" showLabels size="md" />
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium">Large:</span>
                <ThemeToggle layout="buttons" showLabels size="lg" />
              </div>
            </div>
          </DemoSection>

          {/* Style Variants */}
          <DemoSection
            title="Style Variants"
            description="Different visual styles for integration flexibility"
          >
            <div className="space-y-4">
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium w-16">Default:</span>
                <ThemeToggle layout="buttons" showLabels variant="default" />
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium w-16">Subtle:</span>
                <ThemeToggle layout="buttons" showLabels variant="subtle" />
              </div>
              <div className="flex items-center space-x-4">
                <span className="text-sm font-medium w-16">Outline:</span>
                <ThemeToggle layout="buttons" showLabels variant="outline" />
              </div>
            </div>
          </DemoSection>

          {/* Integration Examples */}
          <DemoSection
            title="Integration Examples"
            description="Real-world usage examples"
          >
            <div className="space-y-6 w-full">
              {/* Header-style integration */}
              <div className="flex items-center justify-between p-4 bg-muted/50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className="h-8 w-8 rounded bg-primary flex items-center justify-center text-primary-foreground text-sm font-bold">
                    A
                  </div>
                  <span className="font-medium">App Header</span>
                </div>
                <div className="flex items-center space-x-2">
                  <ThemeToggle layout="compact" variant="subtle" />
                </div>
              </div>

              {/* Settings page style */}
              <div className="p-4 border border-border rounded-lg">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h4 className="font-medium">Appearance</h4>
                    <p className="text-sm text-muted-foreground">
                      Choose your preferred theme
                    </p>
                  </div>
                </div>
                <ThemeToggle layout="buttons" showLabels includeSystem variant="outline" />
              </div>

              {/* Dropdown in menu */}
              <div className="p-4 bg-card border border-border rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Theme Settings</span>
                  <ThemeToggle layout="dropdown" includeSystem />
                </div>
              </div>
            </div>
          </DemoSection>
        </div>

        {/* Usage Notes */}
        <Card>
          <CardHeader>
            <CardTitle>Usage Guidelines</CardTitle>
            <CardDescription>
              Best practices for using theme toggles in your application
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4 text-sm">
              <div>
                <h4 className="font-medium mb-1">Layout Selection:</h4>
                <ul className="text-muted-foreground space-y-1 ml-4">
                  <li>• <strong>Compact:</strong> Use in headers, toolbars, or when space is limited</li>
                  <li>• <strong>Buttons:</strong> Best for settings pages or when theme selection is primary</li>
                  <li>• <strong>Dropdown:</strong> Good for menus or when you need descriptions</li>
                </ul>
              </div>
              
              <div>
                <h4 className="font-medium mb-1">Accessibility:</h4>
                <ul className="text-muted-foreground space-y-1 ml-4">
                  <li>• All variants include proper ARIA labels and keyboard navigation</li>
                  <li>• Theme indicators provide visual feedback for current selection</li>
                  <li>• Tooltips explain functionality to users</li>
                </ul>
              </div>

              <div>
                <h4 className="font-medium mb-1">System Theme:</h4>
                <ul className="text-muted-foreground space-y-1 ml-4">
                  <li>• Include system option when users prefer automatic switching</li>
                  <li>• System theme follows user's OS dark/light mode preference</li>
                  <li>• Changes automatically when system preference changes</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
}

export default ThemeDemo;