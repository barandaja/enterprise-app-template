import { axe, toHaveNoViolations, JestAxeConfigureOptions } from 'jest-axe'
import { render, RenderResult } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// Extend Jest matchers
expect.extend(toHaveNoViolations)

// Default axe configuration for consistent testing
const defaultAxeConfig: JestAxeConfigureOptions = {
  rules: {
    // Enable all WCAG 2.1 AA rules
    'wcag2a': { enabled: true },
    'wcag2aa': { enabled: true },
    'wcag21aa': { enabled: true },
    
    // Additional best practice rules
    'best-practice': { enabled: true },
    
    // Disable rules that may be too strict for testing
    'color-contrast': { enabled: true },
    'landmark-one-main': { enabled: false }, // May not apply to all components
    'region': { enabled: false }, // May not apply to isolated components
  },
  tags: ['wcag2a', 'wcag2aa', 'wcag21aa', 'best-practice'],
}

// Enhanced accessibility testing utilities
export const a11yUtils = {
  // Test component accessibility
  async testComponentA11y(
    component: RenderResult, 
    config: JestAxeConfigureOptions = defaultAxeConfig
  ) {
    const results = await axe(component.container, config)
    expect(results).toHaveNoViolations()
    return results
  },

  // Test keyboard navigation
  async testKeyboardNavigation(component: RenderResult) {
    const user = userEvent.setup()
    const focusableElements = component.container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )

    if (focusableElements.length === 0) {
      console.warn('No focusable elements found for keyboard navigation test')
      return { passed: true, elements: [] }
    }

    const navigationResults = []

    // Test Tab navigation
    for (let i = 0; i < focusableElements.length; i++) {
      await user.tab()
      const activeElement = document.activeElement
      const expectedElement = focusableElements[i]
      
      navigationResults.push({
        index: i,
        expected: expectedElement,
        actual: activeElement,
        matches: activeElement === expectedElement,
        tagName: expectedElement.tagName,
        role: expectedElement.getAttribute('role'),
        ariaLabel: expectedElement.getAttribute('aria-label'),
      })
    }

    // Test Shift+Tab navigation (reverse)
    for (let i = focusableElements.length - 1; i >= 0; i--) {
      await user.tab({ shift: true })
      const activeElement = document.activeElement
      const expectedElement = focusableElements[i]
      
      navigationResults.push({
        index: i,
        expected: expectedElement,
        actual: activeElement,
        matches: activeElement === expectedElement,
        direction: 'reverse',
        tagName: expectedElement.tagName,
        role: expectedElement.getAttribute('role'),
        ariaLabel: expectedElement.getAttribute('aria-label'),
      })
    }

    const allMatched = navigationResults.every(result => result.matches)
    
    return {
      passed: allMatched,
      elements: focusableElements,
      results: navigationResults,
      summary: {
        total: focusableElements.length,
        passed: navigationResults.filter(r => r.matches).length,
        failed: navigationResults.filter(r => !r.matches).length,
      }
    }
  },

  // Test screen reader compatibility
  async testScreenReaderCompatibility(component: RenderResult) {
    const violations = []
    
    // Check for missing alt text on images
    const images = component.container.querySelectorAll('img')
    images.forEach((img, index) => {
      const alt = img.getAttribute('alt')
      const ariaLabel = img.getAttribute('aria-label')
      const ariaLabelledBy = img.getAttribute('aria-labelledby')
      
      if (!alt && !ariaLabel && !ariaLabelledBy) {
        violations.push({
          type: 'missing-alt-text',
          element: img,
          message: `Image ${index + 1} is missing alt text or aria-label`,
          severity: 'error'
        })
      }
    })

    // Check for missing labels on form controls
    const formControls = component.container.querySelectorAll('input, select, textarea')
    formControls.forEach((control, index) => {
      const label = component.container.querySelector(`label[for="${control.id}"]`)
      const ariaLabel = control.getAttribute('aria-label')
      const ariaLabelledBy = control.getAttribute('aria-labelledby')
      
      if (!label && !ariaLabel && !ariaLabelledBy) {
        violations.push({
          type: 'missing-form-label',
          element: control,
          message: `Form control ${index + 1} is missing a label`,
          severity: 'error'
        })
      }
    })

    // Check for missing button text
    const buttons = component.container.querySelectorAll('button')
    buttons.forEach((button, index) => {
      const text = button.textContent?.trim()
      const ariaLabel = button.getAttribute('aria-label')
      const ariaLabelledBy = button.getAttribute('aria-labelledby')
      
      if (!text && !ariaLabel && !ariaLabelledBy) {
        violations.push({
          type: 'missing-button-text',
          element: button,
          message: `Button ${index + 1} has no accessible text`,
          severity: 'error'
        })
      }
    })

    // Check for proper heading hierarchy
    const headings = Array.from(component.container.querySelectorAll('h1, h2, h3, h4, h5, h6'))
    if (headings.length > 0) {
      const headingLevels = headings.map(heading => parseInt(heading.tagName[1]))
      
      for (let i = 1; i < headingLevels.length; i++) {
        const current = headingLevels[i]
        const previous = headingLevels[i - 1]
        
        if (current > previous + 1) {
          violations.push({
            type: 'heading-hierarchy-skip',
            element: headings[i],
            message: `Heading level ${current} follows level ${previous}, skipping levels`,
            severity: 'warning'
          })
        }
      }
    }

    // Check for proper ARIA attributes
    const elementsWithAria = component.container.querySelectorAll('[aria-describedby], [aria-labelledby]')
    elementsWithAria.forEach((element, index) => {
      const describedBy = element.getAttribute('aria-describedby')
      const labelledBy = element.getAttribute('aria-labelledby')
      
      if (describedBy) {
        const referencedElement = component.container.querySelector(`#${describedBy}`)
        if (!referencedElement) {
          violations.push({
            type: 'broken-aria-reference',
            element,
            message: `Element references non-existent ID in aria-describedby: ${describedBy}`,
            severity: 'error'
          })
        }
      }
      
      if (labelledBy) {
        const referencedElement = component.container.querySelector(`#${labelledBy}`)
        if (!referencedElement) {
          violations.push({
            type: 'broken-aria-reference',
            element,
            message: `Element references non-existent ID in aria-labelledby: ${labelledBy}`,
            severity: 'error'
          })
        }
      }
    })

    return {
      passed: violations.length === 0,
      violations,
      summary: {
        total: violations.length,
        errors: violations.filter(v => v.severity === 'error').length,
        warnings: violations.filter(v => v.severity === 'warning').length,
      }
    }
  },

  // Test color contrast
  async testColorContrast(component: RenderResult) {
    // Note: This is a simplified test. In practice, you'd use a more sophisticated
    // color contrast analyzer or rely on axe-core's color-contrast rule
    const textElements = component.container.querySelectorAll('*')
    const contrastIssues = []
    
    textElements.forEach((element, index) => {
      const computedStyle = window.getComputedStyle(element)
      const color = computedStyle.color
      const backgroundColor = computedStyle.backgroundColor
      
      // Simple heuristic check (in practice, use proper contrast ratio calculation)
      if (color === backgroundColor) {
        contrastIssues.push({
          element,
          message: `Element ${index + 1} has same color and background-color`,
          color,
          backgroundColor,
        })
      }
    })

    return {
      passed: contrastIssues.length === 0,
      issues: contrastIssues,
      summary: {
        elementsChecked: textElements.length,
        issuesFound: contrastIssues.length,
      }
    }
  },

  // Test focus management
  async testFocusManagement(component: RenderResult) {
    const user = userEvent.setup()
    const focusableElements = component.container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )

    const issues = []

    // Test that all focusable elements can receive focus
    for (const element of Array.from(focusableElements)) {
      try {
        ;(element as HTMLElement).focus()
        if (document.activeElement !== element) {
          issues.push({
            type: 'cannot-focus',
            element,
            message: 'Element cannot receive focus programmatically',
          })
        }
      } catch (error) {
        issues.push({
          type: 'focus-error',
          element,
          message: `Error focusing element: ${error.message}`,
        })
      }
    }

    // Test focus indicators (elements should have visible focus styles)
    for (const element of Array.from(focusableElements)) {
      ;(element as HTMLElement).focus()
      const computedStyle = window.getComputedStyle(element)
      const outline = computedStyle.outline
      const outlineWidth = computedStyle.outlineWidth
      const boxShadow = computedStyle.boxShadow
      
      if (outline === 'none' && outlineWidth === '0px' && !boxShadow.includes('inset')) {
        issues.push({
          type: 'no-focus-indicator',
          element,
          message: 'Element lacks visible focus indicator',
        })
      }
    }

    // Test focus trap (if modal or dialog)
    const modals = component.container.querySelectorAll('[role="dialog"], .modal')
    for (const modal of Array.from(modals)) {
      const modalFocusableElements = modal.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
      
      if (modalFocusableElements.length > 0) {
        const firstElement = modalFocusableElements[0] as HTMLElement
        const lastElement = modalFocusableElements[modalFocusableElements.length - 1] as HTMLElement
        
        // Test focus doesn't escape modal
        lastElement.focus()
        await user.tab()
        
        if (document.activeElement !== firstElement) {
          issues.push({
            type: 'focus-trap-failure',
            element: modal,
            message: 'Focus escapes modal dialog',
          })
        }
      }
    }

    return {
      passed: issues.length === 0,
      issues,
      summary: {
        focusableElements: focusableElements.length,
        issuesFound: issues.length,
      }
    }
  },

  // Test ARIA roles and states
  async testAriaRolesAndStates(component: RenderResult) {
    const issues = []
    
    // Check for proper button roles
    const buttons = component.container.querySelectorAll('button, [role="button"]')
    buttons.forEach((button, index) => {
      const ariaPressed = button.getAttribute('aria-pressed')
      const ariaExpanded = button.getAttribute('aria-expanded')
      
      // If button has aria-pressed, it should be a valid value
      if (ariaPressed && !['true', 'false', 'mixed'].includes(ariaPressed)) {
        issues.push({
          type: 'invalid-aria-pressed',
          element: button,
          message: `Button ${index + 1} has invalid aria-pressed value: ${ariaPressed}`,
        })
      }
      
      // If button has aria-expanded, it should be a valid value
      if (ariaExpanded && !['true', 'false'].includes(ariaExpanded)) {
        issues.push({
          type: 'invalid-aria-expanded',
          element: button,
          message: `Button ${index + 1} has invalid aria-expanded value: ${ariaExpanded}`,
        })
      }
    })

    // Check for proper input roles and states
    const inputs = component.container.querySelectorAll('input')
    inputs.forEach((input, index) => {
      const ariaInvalid = input.getAttribute('aria-invalid')
      const ariaRequired = input.getAttribute('aria-required')
      
      if (ariaInvalid && !['true', 'false', 'grammar', 'spelling'].includes(ariaInvalid)) {
        issues.push({
          type: 'invalid-aria-invalid',
          element: input,
          message: `Input ${index + 1} has invalid aria-invalid value: ${ariaInvalid}`,
        })
      }
      
      if (ariaRequired && !['true', 'false'].includes(ariaRequired)) {
        issues.push({
          type: 'invalid-aria-required',
          element: input,
          message: `Input ${index + 1} has invalid aria-required value: ${ariaRequired}`,
        })
      }
    })

    // Check for proper list structures
    const lists = component.container.querySelectorAll('ul, ol, [role="list"]')
    lists.forEach((list, index) => {
      const listItems = list.querySelectorAll('li, [role="listitem"]')
      if (listItems.length === 0) {
        issues.push({
          type: 'empty-list',
          element: list,
          message: `List ${index + 1} contains no list items`,
        })
      }
    })

    return {
      passed: issues.length === 0,
      issues,
      summary: {
        elementsChecked: buttons.length + inputs.length + lists.length,
        issuesFound: issues.length,
      }
    }
  },

  // Comprehensive accessibility test
  async runFullA11yTest(component: RenderResult) {
    const results = {
      axeResults: await a11yUtils.testComponentA11y(component),
      keyboardNav: await a11yUtils.testKeyboardNavigation(component),
      screenReader: await a11yUtils.testScreenReaderCompatibility(component),
      colorContrast: await a11yUtils.testColorContrast(component),
      focusManagement: await a11yUtils.testFocusManagement(component),
      ariaRolesStates: await a11yUtils.testAriaRolesAndStates(component),
    }

    const allPassed = Object.values(results).every(result => result.passed)
    
    const summary = {
      passed: allPassed,
      tests: {
        axe: results.axeResults.violations?.length === 0,
        keyboardNavigation: results.keyboardNav.passed,
        screenReaderCompatibility: results.screenReader.passed,
        colorContrast: results.colorContrast.passed,
        focusManagement: results.focusManagement.passed,
        ariaRolesAndStates: results.ariaRolesStates.passed,
      },
      totalIssues: (results.axeResults.violations?.length || 0) +
                   (results.screenReader.violations?.length || 0) +
                   (results.colorContrast.issues?.length || 0) +
                   (results.focusManagement.issues?.length || 0) +
                   (results.ariaRolesStates.issues?.length || 0),
    }

    return {
      ...results,
      summary,
    }
  },
}

// Custom Jest matchers for accessibility testing
export const a11yMatchers = {
  toBeAccessible: async (received: RenderResult) => {
    const results = await a11yUtils.runFullA11yTest(received)
    
    return {
      message: () => 
        results.summary.passed
          ? 'Component is accessible'
          : `Component has ${results.summary.totalIssues} accessibility issues`,
      pass: results.summary.passed,
    }
  },

  toHaveGoodKeyboardNavigation: async (received: RenderResult) => {
    const results = await a11yUtils.testKeyboardNavigation(received)
    
    return {
      message: () =>
        results.passed
          ? 'Component has good keyboard navigation'
          : `Keyboard navigation issues: ${results.summary?.failed || 0} failed`,
      pass: results.passed,
    }
  },

  toBeScreenReaderFriendly: async (received: RenderResult) => {
    const results = await a11yUtils.testScreenReaderCompatibility(received)
    
    return {
      message: () =>
        results.passed
          ? 'Component is screen reader friendly'
          : `Screen reader issues: ${results.violations?.length || 0} violations`,
      pass: results.passed,
    }
  },
}

// Helper to create accessible test scenarios
export const createA11yTestScenario = (componentName: string) => ({
  name: componentName,
  tests: [
    {
      name: 'should be accessible',
      test: async (component: RenderResult) => {
        await expect(component).toBeAccessible()
      },
    },
    {
      name: 'should have good keyboard navigation',
      test: async (component: RenderResult) => {
        await expect(component).toHaveGoodKeyboardNavigation()
      },
    },
    {
      name: 'should be screen reader friendly',
      test: async (component: RenderResult) => {
        await expect(component).toBeScreenReaderFriendly()
      },
    },
    {
      name: 'should pass axe tests',
      test: async (component: RenderResult) => {
        const results = await axe(component.container)
        expect(results).toHaveNoViolations()
      },
    },
  ],
})

// Extend expect with custom matchers
expect.extend(a11yMatchers)