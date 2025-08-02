// Essential UI Components
export { Button, type ButtonProps, type ButtonVariant, type ButtonSize } from './Button';

export { 
  Input, 
  Textarea, 
  FormField,
  type InputProps, 
  type TextareaProps, 
  type FormFieldProps 
} from './Input';

export { 
  Card, 
  CardHeader, 
  CardTitle, 
  CardDescription, 
  CardContent, 
  CardFooter,
  CardComponent,
  type CardProps,
  type CardHeaderProps,
  type CardTitleProps,
  type CardDescriptionProps,
  type CardContentProps,
  type CardFooterProps
} from './Card';

export { 
  Modal, 
  ModalHeader, 
  ModalTitle, 
  ModalDescription, 
  ModalContent, 
  ModalFooter,
  type ModalProps,
  type ModalSize,
  type ModalHeaderProps,
  type ModalTitleProps,
  type ModalDescriptionProps,
  type ModalContentProps,
  type ModalFooterProps
} from './Modal';

export { 
  Alert, 
  SuccessAlert, 
  ErrorAlert, 
  WarningAlert, 
  InfoAlert,
  AlertContent,
  type AlertProps,
  type AlertType,
  type AlertContentProps
} from './Alert';

export { 
  Spinner, 
  DotsSpinner, 
  PulseSpinner, 
  LoadingOverlay, 
  InlineLoading,
  type SpinnerProps,
  type SpinnerSize,
  type DotsSpinnerProps,
  type PulseSpinnerProps,
  type LoadingOverlayProps,
  type InlineLoadingProps
} from './Spinner';

export { CSRFToken, useCSRFToken } from './CSRFToken';

export { 
  SecureFileUpload,
  type SecureFileUploadProps
} from './SecureFileUpload';

export {
  PasswordStrengthMeter,
  usePasswordStrengthMeter,
  type PasswordStrengthMeterProps
} from './PasswordStrengthMeter';

export {
  SecurePasswordInput,
  PasswordConfirmationInput,
  type SecurePasswordInputProps,
  type PasswordConfirmationInputProps
} from './SecurePasswordInput';

export {
  RateLimitedButton,
  useRateLimitedForm,
  type RateLimitedButtonProps
} from './RateLimitedButton';

export {
  ErrorBoundary,
  withErrorBoundary,
  useErrorHandler
} from './ErrorBoundary';

export {
  AsyncBoundary,
  DataBoundary,
  RouteAsyncBoundary,
  SectionAsyncBoundary,
  ListAsyncBoundary,
  withAsyncBoundary
} from './AsyncBoundary';

export {
  ConsentBanner,
  ConsentSettings
} from './ConsentBanner';

export {
  DataPrivacySettings
} from './DataPrivacy';

export {
  AgeVerification,
  AgeRestricted,
  useAgeVerification,
  type AgeVerificationProps
} from './AgeVerification';

// Usage examples and quick reference:
/*
// Import individual components
import { Button, Input, Card } from '@/components';

// Import with types
import { Button, type ButtonProps } from '@/components';

// Import specific component modules
import { CardComponent } from '@/components';

// Basic usage examples:

// Button
<Button variant="primary" size="lg" loading={isLoading}>
  Submit
</Button>

// Input with validation
<Input
  label="Email"
  type="email"
  error={errors.email?.message}
  leftIcon={<EmailIcon />}
  {...register('email')}
/>

// Card composition
<Card>
  <CardHeader>
    <CardTitle>Settings</CardTitle>
    <CardDescription>Manage your account settings</CardDescription>
  </CardHeader>
  <CardContent>
    <form>...</form>
  </CardContent>
  <CardFooter>
    <Button>Save Changes</Button>
  </CardFooter>
</Card>

// Modal
<Modal isOpen={isOpen} onClose={() => setIsOpen(false)}>
  <ModalHeader>
    <ModalTitle>Confirm Action</ModalTitle>
  </ModalHeader>
  <ModalContent>
    <p>Are you sure?</p>
  </ModalContent>
  <ModalFooter>
    <Button variant="outline" onClick={() => setIsOpen(false)}>Cancel</Button>
    <Button variant="destructive">Delete</Button>
  </ModalFooter>
</Modal>

// Alert
<Alert type="success" title="Success!" description="Changes saved." dismissible />

// Loading states
<Spinner size="lg" />
<LoadingOverlay isLoading={loading}>
  <YourContent />
</LoadingOverlay>
*/