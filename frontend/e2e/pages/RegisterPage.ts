import { Page, Locator } from '@playwright/test'
import { BasePage } from './BasePage'

export class RegisterPage extends BasePage {
  readonly nameInput: Locator
  readonly emailInput: Locator
  readonly passwordInput: Locator
  readonly confirmPasswordInput: Locator
  readonly termsCheckbox: Locator
  readonly privacyCheckbox: Locator
  readonly registerButton: Locator
  readonly loginLink: Locator
  readonly errorMessage: Locator
  readonly successMessage: Locator
  readonly loadingSpinner: Locator
  readonly passwordStrengthMeter: Locator
  readonly ageVerification: Locator

  constructor(page: Page) {
    super(page)
    this.nameInput = page.getByLabel(/name/i)
    this.emailInput = page.getByLabel(/email/i)
    this.passwordInput = page.getByLabel(/^password/i)
    this.confirmPasswordInput = page.getByLabel(/confirm password/i)
    this.termsCheckbox = page.getByLabel(/terms/i)
    this.privacyCheckbox = page.getByLabel(/privacy/i)
    this.registerButton = page.getByRole('button', { name: /register|sign up/i })
    this.loginLink = page.getByRole('link', { name: /login|sign in/i })
    this.errorMessage = page.getByTestId('error-message')
    this.successMessage = page.getByTestId('success-message')
    this.loadingSpinner = page.getByTestId('loading-spinner')
    this.passwordStrengthMeter = page.getByTestId('password-strength')
    this.ageVerification = page.getByTestId('age-verification')
  }

  async goto() {
    await super.goto('/register')
  }

  async register(userData: {
    name: string
    email: string
    password: string
    confirmPassword?: string
    acceptTerms?: boolean
    acceptPrivacy?: boolean
    age?: number
  }) {
    await this.fillInput(this.nameInput, userData.name)
    await this.fillInput(this.emailInput, userData.email)
    await this.fillInput(this.passwordInput, userData.password)
    
    if (userData.confirmPassword !== undefined) {
      await this.fillInput(this.confirmPasswordInput, userData.confirmPassword)
    } else {
      await this.fillInput(this.confirmPasswordInput, userData.password)
    }

    if (userData.acceptTerms !== false) {
      await this.clickElement(this.termsCheckbox)
    }

    if (userData.acceptPrivacy !== false) {
      await this.clickElement(this.privacyCheckbox)
    }

    // Handle age verification if present
    if (userData.age) {
      const ageInput = this.page.getByLabel(/age/i)
      if (await ageInput.count() > 0) {
        await this.fillInput(ageInput, userData.age.toString())
      }
    }

    await this.clickElement(this.registerButton)
  }

  async registerWithValidData() {
    await this.register({
      name: 'Test User',
      email: 'newuser@example.com',
      password: 'SecurePassword123!',
      age: 25
    })
  }

  async registerWithExistingEmail() {
    await this.register({
      name: 'Test User',
      email: 'existing@example.com',
      password: 'SecurePassword123!'
    })
  }

  async registerWithWeakPassword() {
    await this.register({
      name: 'Test User',
      email: 'test@example.com',
      password: '123'
    })
  }

  async registerWithMismatchedPasswords() {
    await this.register({
      name: 'Test User',
      email: 'test@example.com',
      password: 'SecurePassword123!',
      confirmPassword: 'DifferentPassword456!'
    })
  }

  async expectRegistrationSuccess() {
    await this.expectElementVisible(this.successMessage)
    await this.expectText(this.successMessage, /success|registered/i)
  }

  async expectRegistrationError(errorText?: string) {
    await this.expectElementVisible(this.errorMessage)
    if (errorText) {
      await this.expectText(this.errorMessage, errorText)
    }
  }

  async expectPasswordStrength(level: 'weak' | 'medium' | 'strong') {
    await this.expectElementVisible(this.passwordStrengthMeter)
    await this.expectText(this.passwordStrengthMeter, new RegExp(level, 'i'))
  }

  async waitForRegistrationComplete() {
    await Promise.race([
      this.successMessage.waitFor({ state: 'visible' }),
      this.errorMessage.waitFor({ state: 'visible' })
    ])
  }

  async goToLogin() {
    await this.clickElement(this.loginLink)
    await this.expectUrl(/\/login/)
  }

  // Security testing methods
  async testInputSanitization() {
    const maliciousInputs = [
      '<script>alert("XSS")</script>',
      '"; DROP TABLE users; --',
      '${7*7}',
      'javascript:alert("XSS")',
      '<img src=x onerror=alert("XSS")>'
    ]

    const results = []

    for (const input of maliciousInputs) {
      await this.register({
        name: input,
        email: 'test@example.com',
        password: 'SecurePassword123!'
      })

      // Check if malicious input was sanitized
      const hasError = await this.errorMessage.count() > 0
      const hasSuccess = await this.successMessage.count() > 0

      results.push({
        input,
        blocked: hasError,
        allowed: hasSuccess
      })

      // Reset form
      await this.page.reload()
    }

    return results
  }

  async testPasswordRequirements() {
    const passwords = [
      { password: '123', expected: 'weak' },
      { password: 'password', expected: 'weak' },
      { password: 'Password123', expected: 'medium' },
      { password: 'SecurePassword123!', expected: 'strong' }
    ]

    const results = []

    for (const { password, expected } of passwords) {
      await this.fillInput(this.passwordInput, password)
      
      // Wait for password strength calculation
      await this.page.waitForTimeout(500)
      
      const strengthText = await this.passwordStrengthMeter.textContent()
      const meetsRequirement = strengthText?.toLowerCase().includes(expected.toLowerCase())
      
      results.push({
        password,
        expected,
        actual: strengthText,
        meets: meetsRequirement
      })
      
      // Clear field
      await this.passwordInput.clear()
    }

    return results
  }

  async testEmailValidation() {
    const emails = [
      { email: 'invalid', valid: false },
      { email: 'invalid@', valid: false },
      { email: 'invalid@domain', valid: false },
      { email: '@domain.com', valid: false },
      { email: 'valid@domain.com', valid: true },
      { email: 'user.name+tag@domain.co.uk', valid: true }
    ]

    const results = []

    for (const { email, valid } of emails) {
      await this.fillInput(this.emailInput, email)
      await this.clickElement(this.registerButton)

      const hasValidationError = await this.page.locator('input[type="email"]:invalid').count() > 0
      const hasFormError = await this.errorMessage.count() > 0

      results.push({
        email,
        expectedValid: valid,
        hasValidationError,
        hasFormError,
        actualValid: !hasValidationError && !hasFormError
      })

      // Reset
      await this.emailInput.clear()
      if (await this.errorMessage.count() > 0) {
        await this.page.reload()
      }
    }

    return results
  }

  async testAgeVerification() {
    const ages = [
      { age: 12, shouldBlock: true },
      { age: 17, shouldBlock: true },
      { age: 18, shouldBlock: false },
      { age: 25, shouldBlock: false }
    ]

    const results = []

    for (const { age, shouldBlock } of ages) {
      await this.register({
        name: 'Test User',
        email: `test${age}@example.com`,
        password: 'SecurePassword123!',
        age
      })

      const blocked = await this.errorMessage.count() > 0
      const ageWarning = await this.page.locator('text=must be 18').count() > 0

      results.push({
        age,
        shouldBlock,
        actuallyBlocked: blocked,
        hasAgeWarning: ageWarning,
        correct: shouldBlock === blocked
      })

      await this.page.reload()
    }

    return results
  }

  async testConsentRequirements() {
    // Try to register without accepting terms
    await this.register({
      name: 'Test User',
      email: 'test@example.com',
      password: 'SecurePassword123!',
      acceptTerms: false,
      acceptPrivacy: false
    })

    const termsError = await this.page.locator('text=terms').count() > 0
    const privacyError = await this.page.locator('text=privacy').count() > 0
    const formBlocked = await this.errorMessage.count() > 0

    return {
      termsError,
      privacyError,
      formBlocked,
      consentRequired: formBlocked || termsError || privacyError
    }
  }

  // Performance testing
  async measureRegistrationPerformance() {
    const startTime = Date.now()
    
    await this.registerWithValidData()
    await this.waitForRegistrationComplete()
    
    const endTime = Date.now()
    return endTime - startTime
  }

  // Accessibility testing
  async checkFormAccessibility() {
    const violations = await super.checkAccessibility()
    
    // Check form labels and ARIA attributes
    const nameLabel = await this.nameInput.getAttribute('aria-label')
    const emailLabel = await this.emailInput.getAttribute('aria-label')
    const passwordLabel = await this.passwordInput.getAttribute('aria-label')
    const confirmPasswordLabel = await this.confirmPasswordInput.getAttribute('aria-label')
    
    // Check required field indicators
    const requiredFields = await this.page.locator('input[required], input[aria-required="true"]').count()
    
    return {
      ...violations,
      hasNameLabel: !!nameLabel,
      hasEmailLabel: !!emailLabel,
      hasPasswordLabel: !!passwordLabel,
      hasConfirmPasswordLabel: !!confirmPasswordLabel,
      requiredFieldsMarked: requiredFields > 0
    }
  }
}