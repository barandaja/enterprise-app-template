import React from 'react';
import { cn } from '../../utils';

// Step definition interface
export interface WizardStep {
  id: string;
  title: string;
  description?: string;
  content: React.ReactNode;
  isOptional?: boolean;
  validation?: () => boolean | Promise<boolean>;
  onEnter?: () => void | Promise<void>;
  onExit?: () => void | Promise<void>;
}

export interface FormWizardProps extends React.HTMLAttributes<HTMLDivElement> {
  steps: WizardStep[];
  currentStep?: number;
  onStepChange?: (step: number, direction: 'next' | 'previous') => void;
  onComplete?: () => void | Promise<void>;
  onCancel?: () => void;
  allowStepNavigation?: boolean;
  showStepNumbers?: boolean;
  showProgress?: boolean;
  nextButtonText?: string;
  previousButtonText?: string;
  finishButtonText?: string;
  cancelButtonText?: string;
  isLoading?: boolean;
  colorScheme?: 'default' | 'primary' | 'success';
}

export const FormWizard = React.forwardRef<HTMLDivElement, FormWizardProps>(
  ({
    steps,
    currentStep = 0,
    onStepChange,
    onComplete,
    onCancel,
    allowStepNavigation = false,
    showStepNumbers = true,
    showProgress = true,
    nextButtonText = 'Next',
    previousButtonText = 'Previous',
    finishButtonText = 'Finish',
    cancelButtonText = 'Cancel',
    isLoading = false,
    colorScheme = 'default',
    className,
    ...props
  }, ref) => {
    const [internalCurrentStep, setInternalCurrentStep] = React.useState(0);
    const [completedSteps, setCompletedSteps] = React.useState<Set<number>>(new Set());
    const [isValidating, setIsValidating] = React.useState(false);

    const activeStep = currentStep ?? internalCurrentStep;
    const currentStepData = steps[activeStep];
    const isFirstStep = activeStep === 0;
    const isLastStep = activeStep === steps.length - 1;
    const progress = ((activeStep + 1) / steps.length) * 100;

    const handleStepChange = async (newStep: number, direction: 'next' | 'previous') => {
      if (newStep < 0 || newStep >= steps.length) return;

      // Validate current step before moving forward
      if (direction === 'next' && currentStepData?.validation) {
        setIsValidating(true);
        try {
          const isValid = await currentStepData.validation();
          if (!isValid) {
            setIsValidating(false);
            return;
          }
        } catch (error) {
          console.error('Step validation failed:', error);
          setIsValidating(false);
          return;
        }
        setIsValidating(false);
      }

      // Call current step's onExit
      if (currentStepData?.onExit) {
        try {
          await currentStepData.onExit();
        } catch (error) {
          console.error('Step exit handler failed:', error);
        }
      }

      // Mark step as completed if moving forward
      if (direction === 'next') {
        setCompletedSteps(prev => new Set([...prev, activeStep]));
      }

      // Update step
      if (currentStep === undefined) {
        setInternalCurrentStep(newStep);
      }
      onStepChange?.(newStep, direction);

      // Call new step's onEnter
      const newStepData = steps[newStep];
      if (newStepData?.onEnter) {
        try {
          await newStepData.onEnter();
        } catch (error) {
          console.error('Step enter handler failed:', error);
        }
      }
    };

    const handleNext = () => {
      if (isLastStep) {
        handleFinish();
      } else {
        handleStepChange(activeStep + 1, 'next');
      }
    };

    const handlePrevious = () => {
      handleStepChange(activeStep - 1, 'previous');
    };

    const handleFinish = async () => {
      // Validate current step first
      if (currentStepData?.validation) {
        setIsValidating(true);
        try {
          const isValid = await currentStepData.validation();
          if (!isValid) {
            setIsValidating(false);
            return;
          }
        } catch (error) {
          console.error('Final step validation failed:', error);
          setIsValidating(false);
          return;
        }
        setIsValidating(false);
      }

      if (onComplete) {
        try {
          await onComplete();
        } catch (error) {
          console.error('Form completion failed:', error);
        }
      }
    };

    const handleStepClick = (stepIndex: number) => {
      if (!allowStepNavigation) return;
      if (stepIndex === activeStep) return;
      
      const direction = stepIndex > activeStep ? 'next' : 'previous';
      handleStepChange(stepIndex, direction);
    };

    const getColorClasses = () => {
      const schemes = {
        default: {
          active: 'bg-primary-600 text-white',
          completed: 'bg-green-600 text-white',
          inactive: 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
          progress: 'bg-primary-600'
        },
        primary: {
          active: 'bg-primary-600 text-white',
          completed: 'bg-primary-800 text-white',
          inactive: 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
          progress: 'bg-primary-600'
        },
        success: {
          active: 'bg-green-600 text-white',
          completed: 'bg-green-800 text-white',
          inactive: 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-400',
          progress: 'bg-green-600'
        }
      };
      return schemes[colorScheme];
    };

    const colors = getColorClasses();

    return (
      <div
        ref={ref}
        className={cn('w-full space-y-6', className)}
        {...props}
      >
        {/* Progress Bar */}
        {showProgress && (
          <div className="w-full bg-gray-200 rounded-full h-2 dark:bg-gray-700">
            <div
              className={cn('h-2 rounded-full transition-all duration-300', colors.progress)}
              style={{ width: `${progress}%` }}
            />
          </div>
        )}

        {/* Steps Navigation */}
        <nav aria-label="Progress" className="mb-8">
          <ol className="flex items-center justify-between">
            {steps.map((step, index) => {
              const isActive = index === activeStep;
              const isCompleted = completedSteps.has(index);
              const isClickable = allowStepNavigation && (isCompleted || index <= activeStep);

              return (
                <li key={step.id} className="flex items-center flex-1">
                  <div className="flex flex-col items-center">
                    {/* Step Circle */}
                    <button
                      type="button"
                      onClick={() => handleStepClick(index)}
                      disabled={!isClickable}
                      className={cn(
                        'flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium transition-colors',
                        isActive && colors.active,
                        isCompleted && !isActive && colors.completed,
                        !isActive && !isCompleted && colors.inactive,
                        isClickable && 'hover:bg-opacity-80 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500',
                        !isClickable && 'cursor-not-allowed'
                      )}
                      aria-current={isActive ? 'step' : undefined}
                    >
                      {isCompleted && !isActive ? (
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                          <path
                            fillRule="evenodd"
                            d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                            clipRule="evenodd"
                          />
                        </svg>
                      ) : showStepNumbers ? (
                        index + 1
                      ) : (
                        <div className="w-2 h-2 rounded-full bg-current" />
                      )}
                    </button>

                    {/* Step Title */}
                    <div className="mt-2 text-center">
                      <p className={cn(
                        'text-sm font-medium',
                        isActive ? 'text-primary-600 dark:text-primary-400' : 'text-gray-500 dark:text-gray-400'
                      )}>
                        {step.title}
                        {step.isOptional && (
                          <span className="text-gray-400 text-xs ml-1">(Optional)</span>
                        )}
                      </p>
                      {step.description && (
                        <p className="text-xs text-gray-400 mt-1">
                          {step.description}
                        </p>
                      )}
                    </div>
                  </div>

                  {/* Connector Line */}
                  {index < steps.length - 1 && (
                    <div className="flex-1 h-px bg-gray-300 dark:bg-gray-600 mx-4 mt-4" />
                  )}
                </li>
              );
            })}
          </ol>
        </nav>

        {/* Step Content */}
        <div className="min-h-[400px]">
          {currentStepData?.content}
        </div>

        {/* Navigation Buttons */}
        <div className="flex justify-between pt-6">
          <div>
            {onCancel && (
              <button
                type="button"
                onClick={onCancel}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-700"
                disabled={isLoading || isValidating}
              >
                {cancelButtonText}
              </button>
            )}
          </div>

          <div className="flex space-x-3">
            {!isFirstStep && (
              <button
                type="button"
                onClick={handlePrevious}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-700"
                disabled={isLoading || isValidating}
              >
                {previousButtonText}
              </button>
            )}

            <button
              type="button"
              onClick={handleNext}
              className="px-4 py-2 text-sm font-medium text-white bg-primary-600 border border-transparent rounded-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={isLoading || isValidating}
            >
              {(isLoading || isValidating) && (
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              )}
              {isLastStep ? finishButtonText : nextButtonText}
            </button>
          </div>
        </div>
      </div>
    );
  }
);

FormWizard.displayName = 'FormWizard';

// Step Component for defining individual steps
export interface StepProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  title?: string;
  description?: string;
}

export const Step = React.forwardRef<HTMLDivElement, StepProps>(
  ({ children, title, description, className, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn('space-y-6', className)}
        {...props}
      >
        {(title || description) && (
          <div className="space-y-1">
            {title && (
              <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
                {title}
              </h2>
            )}
            {description && (
              <p className="text-gray-600 dark:text-gray-400">
                {description}
              </p>
            )}
          </div>
        )}
        <div>{children}</div>
      </div>
    );
  }
);

Step.displayName = 'Step';

export type { WizardStep, FormWizardProps, StepProps };

/*
Usage Examples:

// Basic Form Wizard
const steps: WizardStep[] = [
  {
    id: 'personal',
    title: 'Personal Information',
    description: 'Tell us about yourself',
    content: (
      <Step>
        <FormField label="First Name" required>
          <Input placeholder="John" />
        </FormField>
        <FormField label="Last Name" required>
          <Input placeholder="Doe" />
        </FormField>
      </Step>
    ),
    validation: () => {
      // Validate step data
      return firstName && lastName;
    }
  },
  {
    id: 'contact',
    title: 'Contact Details',
    description: 'How can we reach you?',
    content: (
      <Step>
        <FormField label="Email" required>
          <Input type="email" placeholder="john@example.com" />
        </FormField>
        <FormField label="Phone" isOptional>
          <Input type="tel" placeholder="+1 (555) 123-4567" />
        </FormField>
      </Step>
    ),
    validation: async () => {
      // Async validation
      return await validateEmail(email);
    }
  },
  {
    id: 'review',
    title: 'Review & Submit',
    description: 'Please review your information',
    content: (
      <Step>
        <div className="bg-gray-50 p-4 rounded-md">
          <h3>Review your information</h3>
          <p>First Name: {firstName}</p>
          <p>Last Name: {lastName}</p>
          <p>Email: {email}</p>
        </div>
      </Step>
    )
  }
];

<FormWizard
  steps={steps}
  onComplete={handleFormSubmit}
  onCancel={handleCancel}
  allowStepNavigation
  showProgress
  colorScheme="primary"
/>

// Controlled Wizard
<FormWizard
  steps={steps}
  currentStep={currentStep}
  onStepChange={(step, direction) => {
    setCurrentStep(step);
    // Track analytics
    trackStepChange(step, direction);
  }}
  onComplete={handleComplete}
/>

// Simple Step Component
<Step title="Account Settings" description="Configure your account">
  <FormField label="Username">
    <Input placeholder="johndoe" />
  </FormField>
</Step>
*/