// =============================================================================
// ENTERPRISE UI COMPONENT LIBRARY
// =============================================================================
// Comprehensive React component library for enterprise applications
// Built with TypeScript, Tailwind CSS, and accessibility in mind

// -----------------------------------------------------------------------------
// CORE UI COMPONENTS
// -----------------------------------------------------------------------------

// Enhanced Button Components
export {
  Button,
  ButtonGroup,
  IconButton,
  FAB,
  type ButtonProps,
  type ButtonVariant,
  type ButtonSize,
  type ButtonGroupProps,
  type IconButtonProps,
  type FABProps
} from './Button';

// -----------------------------------------------------------------------------
// INPUT COMPONENTS
// -----------------------------------------------------------------------------

// Base Input Components
export {
  Input,
  Textarea,
  InputGroup,
  InputLeftAddon,
  InputRightAddon,
  type InputProps,
  type InputVariant,
  type InputSize,
  type TextareaProps,
  type InputGroupProps,
  type InputAddonProps
} from './input/Input';

// Specialized Input Components
export {
  TextInput,
  EmailInput,
  PasswordInput,
  type TextInputProps,
  type EmailInputProps,
  type PasswordInputProps
} from './input/TextInput';

export {
  NumberInput,
  PhoneInput,
  type NumberInputProps,
  type PhoneInputProps
} from './input/NumberInput';

// -----------------------------------------------------------------------------
// SELECTION COMPONENTS
// -----------------------------------------------------------------------------

// Single Selection
export {
  Select,
  type SelectProps,
  type SelectOption
} from './selection/Select';

// Multiple Selection
export {
  MultiSelect,
  type MultiSelectProps
} from './selection/MultiSelect';

// Radio Components
export {
  RadioGroup,
  Radio,
  type RadioGroupProps,
  type RadioProps,
  type RadioOption
} from './selection/RadioGroup';

// Checkbox Components
export {
  CheckboxGroup,
  Checkbox,
  type CheckboxGroupProps,
  type CheckboxProps,
  type CheckboxOption
} from './selection/CheckboxGroup';

// -----------------------------------------------------------------------------
// FORM COMPONENTS
// -----------------------------------------------------------------------------

// Form Structure Components
export {
  FormField,
  FormGroup,
  FormSection,
  FormLabel,
  FormErrorMessage,
  FormHelperText,
  type FormFieldProps,
  type FormGroupProps,
  type FormSectionProps,
  type FormLabelProps,
  type FormErrorMessageProps,
  type FormHelperTextProps
} from './form/FormField';

// Advanced Form Components
export {
  FormWizard,
  Step,
  type FormWizardProps,
  type WizardStep,
  type StepProps
} from './form/FormWizard';

export {
  AutoSave,
  useAutoSave,
  type AutoSaveProps,
  type SaveStatus,
  type UseAutoSaveOptions
} from './form/AutoSave';

export {
  FieldArray,
  type FieldArrayProps,
  type FieldArrayActions,
  type FieldArrayItem
} from './form/FieldArray';

// -----------------------------------------------------------------------------
// MEDIA COMPONENTS
// -----------------------------------------------------------------------------

// Avatar Components
export {
  Avatar,
  AvatarGroup,
  type AvatarProps,
  type AvatarGroupProps
} from './media/Avatar';

// -----------------------------------------------------------------------------
// DATA DISPLAY COMPONENTS
// -----------------------------------------------------------------------------

// Table Components
export {
  DataTable,
  type DataTableProps,
  type Column,
  type SortState,
  type FilterState,
  type SelectionState
} from './data-display/DataTable';

// -----------------------------------------------------------------------------
// COMPONENT COMPOSITION UTILITIES
// -----------------------------------------------------------------------------

// Common types used across components
export type ComponentSize = 'xs' | 'sm' | 'md' | 'lg' | 'xl';
export type ComponentVariant = 'default' | 'filled' | 'outline' | 'ghost' | 'solid';
export type ComponentColorScheme = 'primary' | 'secondary' | 'success' | 'warning' | 'danger' | 'info';

// Form validation types
export interface ValidationRule {
  required?: boolean;
  min?: number;
  max?: number;
  pattern?: RegExp;
  custom?: (value: any) => string | undefined;
}

export interface FieldState {
  value: any;
  error?: string;
  touched: boolean;
  dirty: boolean;
}

// Accessibility helpers
export interface AriaProps {
  'aria-label'?: string;
  'aria-labelledby'?: string;
  'aria-describedby'?: string;
  'aria-required'?: boolean;
  'aria-invalid'?: boolean;
  'aria-expanded'?: boolean;
  'aria-selected'?: boolean;
  'aria-checked'?: boolean;
  'aria-disabled'?: boolean;
  role?: string;
}

// Loading and async states
export interface AsyncState<T = any> {
  data?: T;
  loading: boolean;
  error?: string;
}

// Pagination types
export interface PaginationState {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

// Sort and filter types
export interface SortState {
  field: string;
  direction: 'asc' | 'desc';
}

export interface FilterState {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'contains' | 'startsWith' | 'endsWith';
  value: any;
}

// Theme and styling types
export interface ThemeColors {
  primary: string;
  secondary: string;
  success: string;
  warning: string;
  danger: string;
  info: string;
  light: string;
  dark: string;
}

export interface ComponentTheme {
  colors: ThemeColors;
  spacing: Record<string, string>;
  borderRadius: Record<string, string>;
  shadows: Record<string, string>;
  typography: Record<string, string>;
}

// -----------------------------------------------------------------------------
// USAGE EXAMPLES AND DOCUMENTATION
// -----------------------------------------------------------------------------

/*
# Enterprise UI Component Library

A comprehensive React component library built for enterprise applications with a focus on:
- **Accessibility**: WCAG 2.1 AA compliant components
- **TypeScript**: Full type safety and IntelliSense support
- **Tailwind CSS**: Utility-first styling with dark mode support
- **Performance**: Optimized for large-scale applications
- **Extensibility**: Highly customizable and composable components

## Quick Start

```tsx
import { Button, FormField, Input, Select } from '@/ui';

// Basic form example
function ContactForm() {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    country: '',
    message: ''
  });

  return (
    <form className="space-y-6">
      <FormField label="Full Name" required>
        <Input
          value={formData.name}
          onChange={(e) => setFormData({...formData, name: e.target.value})}
          placeholder="Enter your full name"
        />
      </FormField>

      <FormField label="Email Address" required>
        <EmailInput
          value={formData.email}
          onChange={(value) => setFormData({...formData, email: value})}
          validateOnBlur
        />
      </FormField>

      <FormField label="Country">
        <Select
          options={countryOptions}
          value={formData.country}
          onChange={(value) => setFormData({...formData, country: value})}
          searchable
        />
      </FormField>

      <FormField label="Message">
        <Textarea
          value={formData.message}
          onChange={(e) => setFormData({...formData, message: e.target.value})}
          rows={4}
        />
      </FormField>

      <Button type="submit" size="lg" fullWidth>
        Send Message
      </Button>
    </form>
  );
}
```

## Advanced Examples

```tsx
// Multi-step form with auto-save
function AdvancedForm() {
  const [currentStep, setCurrentStep] = useState(0);
  const [formData, setFormData] = useState({});

  const steps: WizardStep[] = [
    {
      id: 'personal',
      title: 'Personal Information',
      content: <PersonalInfoStep />,
      validation: () => validatePersonalInfo(formData)
    },
    {
      id: 'preferences',
      title: 'Preferences',
      content: <PreferencesStep />,
      validation: () => validatePreferences(formData)
    }
  ];

  return (
    <AutoSave
      data={formData}
      onSave={saveFormData}
      storageKey="advanced-form-draft"
    >
      <FormWizard
        steps={steps}
        currentStep={currentStep}
        onStepChange={setCurrentStep}
        onComplete={handleSubmit}
        allowStepNavigation
      />
    </AutoSave>
  );
}
```

## Component Categories

### Input Components
- **TextInput**: Enhanced text input with masks, transformations, and suggestions
- **EmailInput**: Email validation and domain suggestions
- **PasswordInput**: Password strength meter and visibility toggle
- **NumberInput**: Formatted number input with increment/decrement controls
- **PhoneInput**: International phone number formatting

### Selection Components
- **Select**: Single selection dropdown with search and grouping
- **MultiSelect**: Multiple selection with tags and limits
- **RadioGroup**: Radio button groups with card and button variants
- **CheckboxGroup**: Checkbox groups with select-all functionality

### Form Components
- **FormField**: Field wrapper with label, error, and help text
- **FormWizard**: Multi-step form navigation
- **AutoSave**: Automatic form data persistence
- **FieldArray**: Dynamic array of form fields

## Accessibility Features

All components include:
- Proper ARIA labels and roles
- Keyboard navigation support
- Screen reader compatibility
- Focus management
- High contrast mode support
- Semantic HTML structure

## Customization

Components support extensive customization through:
- Size variants (xs, sm, md, lg, xl)
- Color schemes (primary, secondary, success, warning, danger)
- Style variants (default, filled, outline, ghost)
- Custom render functions
- Theme overrides
- CSS class customization

## TypeScript Support

Full TypeScript support with:
- Strict typing for all props
- Generic components where appropriate
- Utility types for common patterns
- IntelliSense for better developer experience

## Performance Considerations

- Components use React.memo where beneficial
- Lazy loading for heavy components
- Virtual scrolling for large lists
- Debounced search and input
- Optimized re-render patterns
*/

// -----------------------------------------------------------------------------
// EXPORTS SUMMARY
// -----------------------------------------------------------------------------

// Total components exported: 25+
// - 4 Button variants
// - 6 Input components  
// - 4 Selection components
// - 6 Form components
// - 2 Media components
// - 1 Data display component
// + Various utility types and interfaces

export default {
  // Component counts for documentation
  totalComponents: 23,
  categories: {
    buttons: 4,
    inputs: 6,
    selections: 4,
    forms: 6,
    media: 2,
    dataDisplay: 1
  },
  
  // Version and metadata
  version: '1.0.0',
  lastUpdated: new Date().toISOString(),
  
  // Feature flags
  features: {
    accessibility: true,
    darkMode: true,
    typescript: true,
    responsive: true,
    i18n: false, // Future feature
    theming: true
  }
};