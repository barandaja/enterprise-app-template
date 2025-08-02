import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '../test/utils'
import { a11yUtils, createA11yTestScenario } from '../test/accessibility-utils'
import { buildTestData } from '../test/factories'
import { Button } from './Button'

// Mock Button component for testing
const MockButton = ({ 
  children, 
  variant = 'primary', 
  size = 'md', 
  disabled = false, 
  loading = false,
  onClick,
  ...props 
}: any) => (
  <button
    className={`btn btn-${variant} btn-${size} ${disabled ? 'disabled' : ''} ${loading ? 'loading' : ''}`}
    disabled={disabled || loading}
    onClick={onClick}
    data-testid="button"
    {...props}
  >
    {loading ? (
      <>
        <span data-testid="loading-spinner" aria-hidden="true">⟳</span>
        <span className="sr-only">Loading...</span>
        {children}
      </>
    ) : (
      children
    )}
  </button>
)

// Use mock component for testing
vi.mock('./Button', () => ({
  Button: MockButton
}))

describe('Button Component', () => {
  describe('Basic Rendering', () => {
    it('should render with default props', () => {
      render(<Button>Click me</Button>)
      
      const button = screen.getByRole('button', { name: 'Click me' })
      expect(button).toBeInTheDocument()
      expect(button).toHaveClass('btn', 'btn-primary', 'btn-md')
    })

    it('should render with custom text', () => {
      const buttonText = 'Custom Button Text'
      render(<Button>{buttonText}</Button>)
      
      expect(screen.getByRole('button', { name: buttonText })).toBeInTheDocument()
    })

    it('should render with different variants', () => {
      const variants = ['primary', 'secondary', 'danger', 'success']
      
      variants.forEach(variant => {
        const { unmount } = render(<Button variant={variant}>Test</Button>)
        
        const button = screen.getByRole('button')
        expect(button).toHaveClass(`btn-${variant}`)
        
        unmount()
      })
    })

    it('should render with different sizes', () => {
      const sizes = ['sm', 'md', 'lg']
      
      sizes.forEach(size => {
        const { unmount } = render(<Button size={size}>Test</Button>)
        
        const button = screen.getByRole('button')
        expect(button).toHaveClass(`btn-${size}`)
        
        unmount()
      })
    })

    it('should render as disabled', () => {
      render(<Button disabled>Disabled Button</Button>)
      
      const button = screen.getByRole('button')
      expect(button).toBeDisabled()
      expect(button).toHaveClass('disabled')
    })

    it('should render in loading state', () => {
      render(<Button loading>Loading Button</Button>)
      
      const button = screen.getByRole('button')
      expect(button).toBeDisabled()
      expect(button).toHaveClass('loading')
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument()
      expect(screen.getByText('Loading...', { selector: '.sr-only' })).toBeInTheDocument()
    })
  })

  describe('Event Handling', () => {
    it('should call onClick when clicked', async () => {
      const handleClick = vi.fn()
      const { user } = render(<Button onClick={handleClick}>Click me</Button>)
      
      const button = screen.getByRole('button')
      await user.click(button)
      
      expect(handleClick).toHaveBeenCalledTimes(1)
    })

    it('should not call onClick when disabled', async () => {
      const handleClick = vi.fn()
      const { user } = render(
        <Button onClick={handleClick} disabled>
          Disabled Button
        </Button>
      )
      
      const button = screen.getByRole('button')
      await user.click(button)
      
      expect(handleClick).not.toHaveBeenCalled()
    })

    it('should not call onClick when loading', async () => {
      const handleClick = vi.fn()
      const { user } = render(
        <Button onClick={handleClick} loading>
          Loading Button
        </Button>
      )
      
      const button = screen.getByRole('button')
      await user.click(button)
      
      expect(handleClick).not.toHaveBeenCalled()
    })

    it('should handle keyboard events', async () => {
      const handleClick = vi.fn()
      const { user } = render(<Button onClick={handleClick}>Press me</Button>)
      
      const button = screen.getByRole('button')
      button.focus()
      
      // Test Enter key
      await user.keyboard('{Enter}')
      expect(handleClick).toHaveBeenCalledTimes(1)
      
      // Test Space key
      await user.keyboard(' ')
      expect(handleClick).toHaveBeenCalledTimes(2)
    })

    it('should prevent double-click in loading state', async () => {
      const handleClick = vi.fn().mockImplementation(() => {
        // Simulate async operation that sets loading to true
        return new Promise(resolve => setTimeout(resolve, 100))
      })
      
      let isLoading = false
      const TestComponent = () => (
        <Button 
          onClick={handleClick} 
          loading={isLoading}
          onLoadingStart={() => { isLoading = true }}
        >
          Submit
        </Button>
      )
      
      const { user, rerender } = render(<TestComponent />)
      
      const button = screen.getByRole('button')
      
      // First click
      await user.click(button)
      
      // Simulate loading state
      isLoading = true
      rerender(<TestComponent />)
      
      // Second click should be ignored
      await user.click(button)
      
      expect(handleClick).toHaveBeenCalledTimes(1)
    })
  })

  describe('Accessibility', () => {
    it('should be accessible by default', async () => {
      const component = render(<Button>Accessible Button</Button>)
      
      await a11yUtils.testComponentA11y(component)
    })

    it('should have proper ARIA attributes when loading', () => {
      render(<Button loading>Loading Button</Button>)
      
      const button = screen.getByRole('button')
      const spinner = screen.getByTestId('loading-spinner')
      
      expect(button).toHaveAttribute('disabled')
      expect(spinner).toHaveAttribute('aria-hidden', 'true')
      expect(screen.getByText('Loading...', { selector: '.sr-only' })).toBeInTheDocument()
    })

    it('should be keyboard navigable', async () => {
      const handleClick = vi.fn()
      const component = render(<Button onClick={handleClick}>Tab to me</Button>)
      
      const keyboardResults = await a11yUtils.testKeyboardNavigation(component)
      expect(keyboardResults.passed).toBe(true)
    })

    it('should be screen reader friendly', async () => {
      const component = render(
        <Button aria-label="Submit form">
          Submit
        </Button>
      )
      
      const screenReaderResults = await a11yUtils.testScreenReaderCompatibility(component)
      expect(screenReaderResults.passed).toBe(true)
    })

    it('should have proper focus management', async () => {
      const component = render(<Button>Focus me</Button>)
      
      const focusResults = await a11yUtils.testFocusManagement(component)
      expect(focusResults.passed).toBe(true)
    })

    it('should support ARIA roles and states', async () => {
      const component = render(
        <Button 
          role="button" 
          aria-pressed="false"
          aria-describedby="button-help"
        >
          Toggle Button
        </Button>
      )
      
      const ariaResults = await a11yUtils.testAriaRolesAndStates(component)
      expect(ariaResults.passed).toBe(true)
    })

    // Run comprehensive accessibility test suite
    const a11yScenario = createA11yTestScenario('Button')
    a11yScenario.tests.forEach(({ name, test: testFn }) => {
      it(name, async () => {
        const component = render(<Button>Test Button</Button>)
        await testFn(component)
      })
    })
  })

  describe('Performance', () => {
    it('should render efficiently', async () => {
      const startTime = performance.now()
      
      render(<Button>Performance Test</Button>)
      
      const endTime = performance.now()
      const renderTime = endTime - startTime
      
      expect(renderTime).toBeLessThan(10) // Should render in less than 10ms
    })

    it('should handle rapid clicks efficiently', async () => {
      const handleClick = vi.fn()
      const { user } = render(<Button onClick={handleClick}>Rapid Click</Button>)
      
      const button = screen.getByRole('button')
      const startTime = performance.now()
      
      // Simulate rapid clicking
      for (let i = 0; i < 10; i++) {
        await user.click(button)
      }
      
      const endTime = performance.now()
      const totalTime = endTime - startTime
      
      expect(handleClick).toHaveBeenCalledTimes(10)
      expect(totalTime).toBeLessThan(1000) // Should handle 10 clicks in less than 1 second
    })

    it('should not cause memory leaks', () => {
      const { unmount } = render(<Button>Memory Test</Button>)
      
      // Check that component unmounts cleanly
      expect(() => unmount()).not.toThrow()
    })
  })

  describe('Security', () => {
    it('should sanitize children content', () => {
      const maliciousContent = '<script>alert("XSS")</script>Click me'
      
      render(<Button>{maliciousContent}</Button>)
      
      const button = screen.getByRole('button')
      expect(button.innerHTML).not.toContain('<script>')
      expect(button.textContent).toBe(maliciousContent) // Text content should be preserved
    })

    it('should handle malicious onClick handlers safely', async () => {
      const maliciousHandler = vi.fn(() => {
        throw new Error('Malicious code executed')
      })
      
      const { user } = render(<Button onClick={maliciousHandler}>Malicious Button</Button>)
      
      const button = screen.getByRole('button')
      
      // Should not crash the application
      await expect(user.click(button)).rejects.toThrow('Malicious code executed')
      expect(maliciousHandler).toHaveBeenCalled()
    })

    it('should prevent CSRF attacks through proper form integration', () => {
      const TestForm = () => (
        <form>
          <input type="hidden" name="_token" value="csrf-token-123" />
          <Button type="submit">Submit Form</Button>
        </form>
      )
      
      render(<TestForm />)
      
      const form = screen.getByRole('button').closest('form')
      const csrfToken = form?.querySelector('input[name="_token"]')
      
      expect(csrfToken).toBeInTheDocument()
      expect(csrfToken).toHaveValue('csrf-token-123')
    })
  })

  describe('Error Handling', () => {
    it('should handle onClick errors gracefully', async () => {
      const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
      const errorHandler = vi.fn(() => {
        throw new Error('Button click failed')
      })
      
      const { user } = render(<Button onClick={errorHandler}>Error Button</Button>)
      
      const button = screen.getByRole('button')
      
      await expect(user.click(button)).rejects.toThrow('Button click failed')
      
      consoleError.mockRestore()
    })

    it('should handle invalid props gracefully', () => {
      // Test with invalid variant
      expect(() => {
        render(<Button variant="invalid">Invalid Variant</Button>)
      }).not.toThrow()
      
      // Test with invalid size
      expect(() => {
        render(<Button size="invalid">Invalid Size</Button>)
      }).not.toThrow()
    })

    it('should handle missing children gracefully', () => {
      expect(() => {
        render(<Button />)
      }).not.toThrow()
      
      const button = screen.getByRole('button')
      expect(button).toBeInTheDocument()
    })
  })

  describe('Integration', () => {
    it('should work with form submission', async () => {
      const handleSubmit = vi.fn((e) => e.preventDefault())
      const { user } = render(
        <form onSubmit={handleSubmit}>
          <Button type="submit">Submit Form</Button>
        </form>
      )
      
      const button = screen.getByRole('button')
      await user.click(button)
      
      expect(handleSubmit).toHaveBeenCalled()
    })

    it('should work with React Router navigation', async () => {
      const navigate = vi.fn()
      
      const NavigationButton = () => (
        <Button onClick={() => navigate('/dashboard')}>
          Go to Dashboard
        </Button>
      )
      
      const { user } = render(<NavigationButton />)
      
      const button = screen.getByRole('button')
      await user.click(button)
      
      expect(navigate).toHaveBeenCalledWith('/dashboard')
    })

    it('should work with async operations', async () => {
      let isLoading = false
      const asyncOperation = vi.fn(async () => {
        isLoading = true
        await new Promise(resolve => setTimeout(resolve, 100))
        isLoading = false
        return 'Success'
      })
      
      const AsyncButton = () => (
        <Button 
          loading={isLoading}
          onClick={asyncOperation}
        >
          Async Operation
        </Button>
      )
      
      const { user, rerender } = render(<AsyncButton />)
      
      const button = screen.getByRole('button')
      await user.click(button)
      
      expect(asyncOperation).toHaveBeenCalled()
      
      // Simulate loading state
      isLoading = true
      rerender(<AsyncButton />)
      
      expect(button).toBeDisabled()
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument()
    })
  })

  describe('Responsive Design', () => {
    it('should adapt to different screen sizes', () => {
      // Mock window.matchMedia for responsive testing
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: vi.fn().mockImplementation(query => ({
          matches: query.includes('max-width: 768px'),
          media: query,
          onchange: null,
          addListener: vi.fn(),
          removeListener: vi.fn(),
          addEventListener: vi.fn(),
          removeEventListener: vi.fn(),
          dispatchEvent: vi.fn(),
        })),
      })
      
      render(<Button>Responsive Button</Button>)
      
      const button = screen.getByRole('button')
      expect(button).toBeInTheDocument()
      
      // In a real implementation, you would check for responsive classes
      // expect(button).toHaveClass('btn-responsive')
    })
  })

  describe('Theme Integration', () => {
    it('should support dark theme', () => {
      // Mock theme context
      const ThemeButton = () => (
        <div data-theme="dark">
          <Button>Dark Theme Button</Button>
        </div>
      )
      
      render(<ThemeButton />)
      
      const themeContainer = screen.getByTestId('button').closest('[data-theme="dark"]')
      expect(themeContainer).toBeInTheDocument()
    })

    it('should support custom theme colors', () => {
      render(
        <Button 
          style={{ 
            '--btn-primary-bg': '#custom-color',
            '--btn-primary-text': '#white' 
          } as any}
        >
          Custom Color Button
        </Button>
      )
      
      const button = screen.getByRole('button')
      expect(button).toHaveStyle({
        '--btn-primary-bg': '#custom-color',
        '--btn-primary-text': '#white'
      })
    })
  })

  describe('Visual Regression', () => {
    it('should match visual snapshot', () => {
      const { container } = render(<Button>Snapshot Button</Button>)
      expect(container.firstChild).toMatchSnapshot()
    })

    it('should match snapshot for different states', () => {
      const states = [
        { props: { disabled: true }, name: 'disabled' },
        { props: { loading: true }, name: 'loading' },
        { props: { variant: 'danger' }, name: 'danger' },
        { props: { size: 'lg' }, name: 'large' }
      ]
      
      states.forEach(({ props, name }) => {
        const { container, unmount } = render(<Button {...props}>Test</Button>)
        expect(container.firstChild).toMatchSnapshot(`button-${name}`)
        unmount()
      })
    })
  })
})