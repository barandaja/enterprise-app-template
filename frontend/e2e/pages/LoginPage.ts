import { Page, Locator } from '@playwright/test'
import { BasePage } from './BasePage'

export class LoginPage extends BasePage {
  readonly emailInput: Locator
  readonly passwordInput: Locator
  readonly loginButton: Locator
  readonly registerLink: Locator
  readonly forgotPasswordLink: Locator
  readonly errorMessage: Locator
  readonly loadingSpinner: Locator
  readonly rememberMeCheckbox: Locator

  constructor(page: Page) {
    super(page)
    this.emailInput = page.getByLabel(/email/i)
    this.passwordInput = page.getByLabel(/password/i)
    this.loginButton = page.getByRole('button', { name: /login|sign in/i })
    this.registerLink = page.getByRole('link', { name: /register|sign up/i })
    this.forgotPasswordLink = page.getByRole('link', { name: /forgot password/i })
    this.errorMessage = page.getByTestId('error-message')
    this.loadingSpinner = page.getByTestId('loading-spinner')
    this.rememberMeCheckbox = page.getByLabel(/remember me/i)
  }

  async goto() {
    await super.goto('/login')
  }

  async login(email: string, password: string, options?: { rememberMe?: boolean }) {
    await this.fillInput(this.emailInput, email)
    await this.fillInput(this.passwordInput, password)
    
    if (options?.rememberMe) {
      await this.clickElement(this.rememberMeCheckbox)
    }
    
    await this.clickElement(this.loginButton)
  }

  async loginWithValidCredentials() {
    await this.login('test@example.com', 'password123')
  }

  async loginWithInvalidCredentials() {
    await this.login('invalid@example.com', 'wrongpassword')
  }

  async expectLoginSuccess() {
    // Should be redirected to dashboard
    await this.expectUrl(/\/dashboard/)
  }

  async expectLoginError(errorText?: string) {
    await this.expectElementVisible(this.errorMessage)
    if (errorText) {
      await this.expectText(this.errorMessage, errorText)
    }
  }

  async expectLoadingState() {
    await this.expectElementVisible(this.loadingSpinner)
  }

  async waitForLoginComplete() {
    // Wait for either success redirect or error message
    await Promise.race([
      this.page.waitForURL(/\/dashboard/),
      this.errorMessage.waitFor({ state: 'visible' })
    ])
  }

  async goToRegister() {
    await this.clickElement(this.registerLink)
    await this.expectUrl(/\/register/)
  }

  async goToForgotPassword() {
    await this.clickElement(this.forgotPasswordLink)
    await this.expectUrl(/\/forgot-password/)
  }

  // Security-specific methods
  async checkCSRFToken() {
    const csrfToken = await this.page.evaluate(() => {
      const metaTag = document.querySelector('meta[name="csrf-token"]')
      return metaTag?.getAttribute('content')
    })
    return csrfToken
  }

  async attemptSQLInjection() {
    await this.login("'; DROP TABLE users; --", 'password')
    await this.expectLoginError()
  }

  async attemptXSSInjection() {
    await this.login('<script>alert("XSS")</script>', 'password')
    await this.expectLoginError()
  }

  async checkPasswordFieldSecurity() {
    // Verify password field is masked
    const passwordType = await this.passwordInput.getAttribute('type')
    return passwordType === 'password'
  }

  async checkFormValidation() {
    // Try to submit empty form
    await this.clickElement(this.loginButton)
    
    // Should show validation errors
    const emailValidation = await this.page.locator('input[type="email"]:invalid').count()
    const passwordValidation = await this.page.locator('input[type="password"]:invalid').count()
    
    return emailValidation > 0 || passwordValidation > 0
  }

  async checkRateLimiting() {
    // Attempt multiple rapid login attempts
    const attempts = 10
    const results = []
    
    for (let i = 0; i < attempts; i++) {
      await this.login('test@example.com', 'wrongpassword')
      
      // Check if rate limited
      const rateLimitError = await this.page.locator('text=too many attempts').count()
      results.push(rateLimitError > 0)
      
      if (rateLimitError > 0) break
    }
    
    return results.some(limited => limited)
  }

  async testBruteForceProtection() {
    const passwords = ['123456', 'password', 'admin', 'test', 'qwerty']
    let blocked = false
    
    for (const password of passwords) {
      await this.login('test@example.com', password)
      
      // Check if account is locked
      const lockMessage = await this.page.locator('text=account locked').count()
      if (lockMessage > 0) {
        blocked = true
        break
      }
      
      await this.page.waitForTimeout(100) // Small delay between attempts
    }
    
    return blocked
  }

  // Accessibility methods
  async checkAccessibility() {
    const violations = await super.checkAccessibility()
    
    // Check form labels
    const emailLabel = await this.emailInput.getAttribute('aria-label')
    const passwordLabel = await this.passwordInput.getAttribute('aria-label')
    
    return {
      ...violations,
      hasEmailLabel: !!emailLabel,
      hasPasswordLabel: !!passwordLabel
    }
  }

  // Performance methods
  async measureLoginPerformance() {
    const startTime = Date.now()
    
    await this.loginWithValidCredentials()
    await this.waitForLoginComplete()
    
    const endTime = Date.now()
    return endTime - startTime
  }
}