import { test, expect } from '@playwright/test'
import { LoginPage } from './pages/LoginPage'
import { RegisterPage } from './pages/RegisterPage'
import { DashboardPage } from './pages/DashboardPage'

test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page, context }) => {
    // Clear storage before each test
    await context.clearCookies()
    await page.evaluate(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
  })

  test.describe('Login Flow', () => {
    test('should login with valid credentials', async ({ page }) => {
      const loginPage = new LoginPage(page)
      const dashboardPage = new DashboardPage(page)

      await loginPage.goto()
      await loginPage.loginWithValidCredentials()
      await loginPage.expectLoginSuccess()
      
      // Should be redirected to dashboard
      await dashboardPage.expectUserAuthenticated('Test User')
    })

    test('should show error for invalid credentials', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      await loginPage.loginWithInvalidCredentials()
      await loginPage.expectLoginError('Invalid credentials')
    })

    test('should validate form fields', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      
      // Try to submit empty form
      const hasValidation = await loginPage.checkFormValidation()
      expect(hasValidation).toBe(true)
    })

    test('should mask password field', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      
      const isPasswordMasked = await loginPage.checkPasswordFieldSecurity()
      expect(isPasswordMasked).toBe(true)
    })

    test('should have CSRF protection', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      
      const csrfToken = await loginPage.checkCSRFToken()
      expect(csrfToken).toBeTruthy()
      expect(csrfToken.length).toBeGreaterThan(10)
    })

    test('should implement rate limiting', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      
      const isRateLimited = await loginPage.checkRateLimiting()
      expect(isRateLimited).toBe(true)
    })

    test('should protect against brute force attacks', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      
      const isBruteForceProtected = await loginPage.testBruteForceProtection()
      expect(isBruteForceProtected).toBe(true)
    })

    test('should be accessible', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      
      const a11yResults = await loginPage.checkAccessibility()
      expect(a11yResults.hasEmailLabel).toBe(true)
      expect(a11yResults.hasPasswordLabel).toBe(true)
      expect(a11yResults.missingAltTexts).toBe(0)
    })

    test('should measure login performance', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      
      const performanceTime = await loginPage.measureLoginPerformance()
      expect(performanceTime).toBeLessThan(3000) // Should complete within 3 seconds
    })

    test('should prevent XSS attacks', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      await loginPage.attemptXSSInjection()
      await loginPage.expectLoginError()
      
      // Check that no XSS payload was executed
      const hasAlert = await page.evaluate(() => {
        return window.alert.toString().includes('XSS')
      }).catch(() => false)
      
      expect(hasAlert).toBe(false)
    })

    test('should prevent SQL injection', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      await loginPage.attemptSQLInjection()
      await loginPage.expectLoginError()
    })
  })

  test.describe('Registration Flow', () => {
    test('should register with valid data', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      await registerPage.registerWithValidData()
      await registerPage.expectRegistrationSuccess()
    })

    test('should show error for existing email', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      await registerPage.registerWithExistingEmail()
      await registerPage.expectRegistrationError('Email already exists')
    })

    test('should validate password strength', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      await registerPage.registerWithWeakPassword()
      await registerPage.expectPasswordStrength('weak')
    })

    test('should validate password confirmation', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      await registerPage.registerWithMismatchedPasswords()
      await registerPage.expectRegistrationError('Passwords do not match')
    })

    test('should sanitize malicious input', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      
      const sanitizationResults = await registerPage.testInputSanitization()
      
      // All malicious inputs should be blocked or sanitized
      sanitizationResults.forEach(result => {
        expect(result.blocked || result.allowed).toBe(true)
        // If allowed, it should be sanitized
        if (result.allowed) {
          expect(result.input).not.toContain('<script>')
          expect(result.input).not.toContain('DROP TABLE')
        }
      })
    })

    test('should validate email format', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      
      const emailValidationResults = await registerPage.testEmailValidation()
      
      emailValidationResults.forEach(result => {
        expect(result.actualValid).toBe(result.expectedValid)
      })
    })

    test('should enforce age verification', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      
      const ageVerificationResults = await registerPage.testAgeVerification()
      
      ageVerificationResults.forEach(result => {
        expect(result.correct).toBe(true)
      })
    })

    test('should require consent', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      
      const consentResults = await registerPage.testConsentRequirements()
      expect(consentResults.consentRequired).toBe(true)
    })

    test('should validate password requirements', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      
      const passwordResults = await registerPage.testPasswordRequirements()
      
      passwordResults.forEach(result => {
        expect(result.meets).toBe(true)
      })
    })

    test('should be accessible', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      
      const a11yResults = await registerPage.checkFormAccessibility()
      expect(a11yResults.hasNameLabel).toBe(true)
      expect(a11yResults.hasEmailLabel).toBe(true)
      expect(a11yResults.hasPasswordLabel).toBe(true)
      expect(a11yResults.requiredFieldsMarked).toBe(true)
    })

    test('should measure registration performance', async ({ page }) => {
      const registerPage = new RegisterPage(page)

      await registerPage.goto()
      
      const performanceTime = await registerPage.measureRegistrationPerformance()
      expect(performanceTime).toBeLessThan(5000) // Should complete within 5 seconds
    })
  })

  test.describe('Dashboard Flow', () => {
    test.beforeEach(async ({ page }) => {
      // Login before each dashboard test
      const loginPage = new LoginPage(page)
      await loginPage.goto()
      await loginPage.loginWithValidCredentials()
      await loginPage.expectLoginSuccess()
    })

    test('should display user information', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      await dashboardPage.expectUserAuthenticated('Test User')
    })

    test('should allow logout', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      await dashboardPage.logout()
    })

    test('should navigate to profile', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      await dashboardPage.goToProfile()
    })

    test('should toggle sidebar', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      
      const sidebarToggled = await dashboardPage.toggleSidebar()
      expect(sidebarToggled).toBe(true)
    })

    test('should toggle theme', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      
      const themeToggled = await dashboardPage.toggleTheme()
      expect(themeToggled).toBe(true)
    })

    test('should handle session timeout', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      
      const sessionExpired = await dashboardPage.checkSessionTimeout()
      expect(sessionExpired).toBe(true)
    })

    test('should have CSRF protection', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      
      const csrfProtected = await dashboardPage.checkCSRFProtection()
      expect(csrfProtected).toBe(true)
    })

    test('should prevent unauthorized access', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      const unauthorized = await dashboardPage.testUnauthorizedAccess()
      expect(unauthorized).toBe(true)
    })

    test('should have secure headers', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      
      const secureHeaders = await dashboardPage.checkSecureHeaders()
      expect(secureHeaders.hasCSP).toBe(true)
      expect(secureHeaders.hasXFrameOptions).toBe(true)
      expect(secureHeaders.hasXContentTypeOptions).toBe(true)
    })

    test('should measure page load performance', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      const loadTime = await dashboardPage.measurePageLoadTime()
      expect(loadTime).toBeLessThan(4000) // Should load within 4 seconds
    })

    test('should persist user preferences', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      
      const persistenceResults = await dashboardPage.testStatePersistence()
      expect(persistenceResults.sidebarPersisted).toBe(true)
      expect(persistenceResults.themePersisted).toBe(true)
    })

    test('should handle errors gracefully', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      
      const errorHandled = await dashboardPage.testErrorBoundary()
      expect(errorHandled).toBe(true)
    })

    test('should be accessible', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      
      const a11yResults = await dashboardPage.checkDashboardAccessibility()
      expect(a11yResults.navigationAccessible).toBe(true)
      expect(a11yResults.mainContentAccessible).toBe(true)
      expect(a11yResults.focusableElementsCount).toBeGreaterThan(0)
    })

    test('should not have console errors', async ({ page }) => {
      const dashboardPage = new DashboardPage(page)

      await dashboardPage.goto()
      await dashboardPage.expectNoConsoleErrors()
    })
  })

  test.describe('Cross-browser Compatibility', () => {
    test('should work in different browsers', async ({ page, browserName }) => {
      const loginPage = new LoginPage(page)
      const dashboardPage = new DashboardPage(page)

      await loginPage.goto()
      await loginPage.loginWithValidCredentials()
      await loginPage.expectLoginSuccess()
      
      await dashboardPage.expectUserAuthenticated('Test User')
      
      // Browser-specific checks
      if (browserName === 'webkit') {
        // Safari-specific tests
        const webkitFeatures = await page.evaluate(() => {
          return {
            hasWebCrypto: !!window.crypto?.subtle,
            hasIndexedDB: !!window.indexedDB,
            hasLocalStorage: !!window.localStorage
          }
        })
        
        expect(webkitFeatures.hasWebCrypto).toBe(true)
        expect(webkitFeatures.hasIndexedDB).toBe(true)
        expect(webkitFeatures.hasLocalStorage).toBe(true)
      }
    })
  })

  test.describe('Mobile Responsiveness', () => {
    test('should work on mobile devices', async ({ page }) => {
      // Set mobile viewport
      await page.setViewportSize({ width: 375, height: 667 })
      
      const loginPage = new LoginPage(page)
      const dashboardPage = new DashboardPage(page)

      await loginPage.goto()
      await loginPage.loginWithValidCredentials()
      await loginPage.expectLoginSuccess()
      
      await dashboardPage.expectUserAuthenticated('Test User')
      
      // Check mobile-specific functionality
      const mobileNavVisible = await page.locator('[data-testid="mobile-nav"]').isVisible()
      expect(mobileNavVisible).toBe(true)
      
      // Test touch interactions
      await page.locator('[data-testid="mobile-menu-toggle"]').tap()
      const mobileMenuOpen = await page.locator('[data-testid="mobile-menu"]').isVisible()
      expect(mobileMenuOpen).toBe(true)
    })
  })

  test.describe('Performance Testing', () => {
    test('should meet performance benchmarks', async ({ page }) => {
      const loginPage = new LoginPage(page)

      // Navigate to login page
      const navigationStart = Date.now()
      await loginPage.goto()
      const navigationEnd = Date.now()
      
      // Check navigation performance
      expect(navigationEnd - navigationStart).toBeLessThan(2000)
      
      // Check Core Web Vitals
      const vitals = await page.evaluate(() => {
        return new Promise((resolve) => {
          new PerformanceObserver((list) => {
            const entries = list.getEntries()
            const vitals = {
              FCP: 0,
              LCP: 0,
              CLS: 0,
              FID: 0
            }
            
            entries.forEach((entry) => {
              if (entry.name === 'first-contentful-paint') {
                vitals.FCP = entry.startTime
              }
              if (entry.entryType === 'largest-contentful-paint') {
                vitals.LCP = entry.startTime
              }
              if (entry.entryType === 'layout-shift' && !entry.hadRecentInput) {
                vitals.CLS += entry.value
              }
              if (entry.entryType === 'first-input') {
                vitals.FID = entry.processingStart - entry.startTime
              }
            })
            
            resolve(vitals)
          }).observe({ entryTypes: ['paint', 'largest-contentful-paint', 'layout-shift', 'first-input'] })
          
          // Timeout after 5 seconds
          setTimeout(() => resolve({ FCP: 0, LCP: 0, CLS: 0, FID: 0 }), 5000)
        })
      })
      
      // Check performance thresholds
      if (vitals.FCP > 0) expect(vitals.FCP).toBeLessThan(2000) // FCP < 2s
      if (vitals.LCP > 0) expect(vitals.LCP).toBeLessThan(4000) // LCP < 4s
      if (vitals.CLS > 0) expect(vitals.CLS).toBeLessThan(0.1)  // CLS < 0.1
      if (vitals.FID > 0) expect(vitals.FID).toBeLessThan(100)  // FID < 100ms
    })
  })

  test.describe('Visual Regression', () => {
    test('should match visual snapshots', async ({ page }) => {
      const loginPage = new LoginPage(page)

      await loginPage.goto()
      
      // Take full page screenshot
      await expect(page).toHaveScreenshot('login-page.png', {
        fullPage: true,
        animations: 'disabled'
      })
      
      // Take component screenshots
      await expect(page.locator('[data-testid="login-form"]')).toHaveScreenshot('login-form.png')
    })

    test('should handle different screen sizes', async ({ page }) => {
      const viewports = [
        { width: 1920, height: 1080 }, // Desktop
        { width: 768, height: 1024 },  // Tablet
        { width: 375, height: 667 }    // Mobile
      ]
      
      for (const viewport of viewports) {
        await page.setViewportSize(viewport)
        
        const loginPage = new LoginPage(page)
        await loginPage.goto()
        
        await expect(page).toHaveScreenshot(`login-${viewport.width}x${viewport.height}.png`, {
          fullPage: true,
          animations: 'disabled'
        })
      }
    })
  })
})