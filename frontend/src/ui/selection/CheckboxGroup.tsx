import React from 'react';
import { cn } from '../../utils';

// Checkbox Option interface
export interface CheckboxOption {
  value: string | number;
  label: string;
  description?: string;
  disabled?: boolean;
  icon?: React.ReactNode;
}

// CheckboxGroup Props
export interface CheckboxGroupProps extends Omit<React.HTMLAttributes<HTMLFieldSetElement>, 'onChange'> {
  options: CheckboxOption[];
  value?: (string | number)[];
  onChange?: (values: (string | number)[], selectedOptions: CheckboxOption[]) => void;
  name?: string;
  label?: string;
  description?: string;
  error?: string;
  helperText?: string;
  required?: boolean;
  disabled?: boolean;
  orientation?: 'horizontal' | 'vertical';
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'card' | 'button';
  colorScheme?: 'primary' | 'secondary' | 'success' | 'warning' | 'danger';
  spacing?: 'sm' | 'md' | 'lg';
  maxSelections?: number;
  minSelections?: number;
  showSelectAll?: boolean;
  indeterminate?: boolean;
  renderOption?: (option: CheckboxOption, isSelected: boolean, isDisabled: boolean) => React.ReactNode;
  onSelectAll?: () => void;
  onDeselectAll?: () => void;
}

export const CheckboxGroup = React.forwardRef<HTMLFieldSetElement, CheckboxGroupProps>(
  ({
    options = [],
    value = [],
    onChange,
    name,
    label,
    description,
    error,
    helperText,
    required = false,
    disabled = false,
    orientation = 'vertical',
    size = 'md',
    variant = 'default',
    colorScheme = 'primary',
    spacing = 'md',
    maxSelections,
    minSelections = 0,
    showSelectAll = false,
    indeterminate = false,
    renderOption,
    onSelectAll,
    onDeselectAll,
    className,
    ...props
  }, ref) => {
    const groupId = name || `checkbox-group-${Math.random().toString(36).substr(2, 9)}`;
    const hasError = !!error;
    const selectedOptions = options.filter(option => value.includes(option.value));
    const canSelectMore = !maxSelections || value.length < maxSelections;
    const canDeselectMore = value.length > minSelections;

    // Select All state
    const allSelected = options.length > 0 && options.every(option => 
      value.includes(option.value) || option.disabled
    );
    const someSelected = value.length > 0 && !allSelected;
    const isIndeterminate = indeterminate || someSelected;

    const handleOptionChange = (option: CheckboxOption) => {
      if (option.disabled || disabled) return;
      
      const isSelected = value.includes(option.value);
      let newValues: (string | number)[];
      
      if (isSelected) {
        // Can't deselect if at minimum
        if (!canDeselectMore) return;
        newValues = value.filter(v => v !== option.value);
      } else {
        // Can't select if at maximum
        if (!canSelectMore) return;
        newValues = [...value, option.value];
      }
      
      const newSelectedOptions = options.filter(opt => newValues.includes(opt.value));
      onChange?.(newValues, newSelectedOptions);
    };

    const handleSelectAll = () => {
      if (allSelected) {
        const newValues = value.filter(v => {
          const option = options.find(opt => opt.value === v);
          return option?.disabled;
        });
        const newSelectedOptions = options.filter(opt => newValues.includes(opt.value));
        onChange?.(newValues, newSelectedOptions);
        onDeselectAll?.();
      } else {
        const availableOptions = options.filter(opt => !opt.disabled);
        const newValues = availableOptions.map(opt => opt.value);
        const limitedValues = maxSelections 
          ? newValues.slice(0, maxSelections)
          : newValues;
        const newSelectedOptions = options.filter(opt => limitedValues.includes(opt.value));
        onChange?.(limitedValues, newSelectedOptions);
        onSelectAll?.();
      }
    };

    const sizeClasses = {
      sm: {
        checkbox: 'h-3 w-3',
        text: 'text-sm',
        spacing: 'space-y-2'
      },
      md: {
        checkbox: 'h-4 w-4',
        text: 'text-sm',
        spacing: 'space-y-3'
      },
      lg: {
        checkbox: 'h-5 w-5',
        text: 'text-base',
        spacing: 'space-y-4'
      }
    };

    const spacingClasses = {
      sm: orientation === 'vertical' ? 'space-y-2' : 'space-x-3',
      md: orientation === 'vertical' ? 'space-y-3' : 'space-x-4',
      lg: orientation === 'vertical' ? 'space-y-4' : 'space-x-6'
    };

    const colorSchemeClasses = {
      primary: {
        checkbox: 'text-primary-600 focus:ring-primary-500',
        button: 'checked:bg-primary-600 checked:border-primary-600 checked:text-white'
      },
      secondary: {
        checkbox: 'text-gray-600 focus:ring-gray-500',
        button: 'checked:bg-gray-600 checked:border-gray-600 checked:text-white'
      },
      success: {
        checkbox: 'text-green-600 focus:ring-green-500',
        button: 'checked:bg-green-600 checked:border-green-600 checked:text-white'
      },
      warning: {
        checkbox: 'text-yellow-600 focus:ring-yellow-500',
        button: 'checked:bg-yellow-600 checked:border-yellow-600 checked:text-white'
      },
      danger: {
        checkbox: 'text-red-600 focus:ring-red-500',
        button: 'checked:bg-red-600 checked:border-red-600 checked:text-white'
      }
    };

    const renderCheckboxOption = (option: CheckboxOption, index: number) => {
      const isSelected = value.includes(option.value);
      const isDisabled = option.disabled || disabled || (!isSelected && !canSelectMore);
      const optionId = `${groupId}-${index}`;

      if (renderOption) {
        return (
          <div key={option.value} className="relative">
            {renderOption(option, isSelected, isDisabled)}
            <input
              type="checkbox"
              id={optionId}
              name={groupId}
              value={option.value}
              checked={isSelected}
              onChange={() => handleOptionChange(option)}
              disabled={isDisabled}
              className="absolute opacity-0 inset-0 w-full h-full cursor-pointer disabled:cursor-not-allowed"
              aria-describedby={option.description ? `${optionId}-description` : undefined}
            />
          </div>
        );
      }

      switch (variant) {
        case 'card':
          return (
            <label
              key={option.value}
              htmlFor={optionId}
              className={cn(
                'relative flex items-start p-4 border rounded-lg cursor-pointer focus-within:ring-2 focus-within:ring-offset-2',
                isSelected 
                  ? 'border-primary-300 bg-primary-50 dark:border-primary-600 dark:bg-primary-900/20'
                  : 'border-gray-300 bg-white hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-800 dark:hover:bg-gray-700',
                isDisabled && 'opacity-50 cursor-not-allowed bg-gray-50 dark:bg-gray-900',
                hasError && 'border-red-300 dark:border-red-600',
                `focus-within:ring-${colorScheme}-500`
              )}
            >
              <input
                type="checkbox"
                id={optionId}
                name={groupId}
                value={option.value}
                checked={isSelected}
                onChange={() => handleOptionChange(option)}
                disabled={isDisabled}
                className={cn(
                  'mt-1 border-gray-300 rounded focus:ring-2 focus:ring-offset-0',
                  sizeClasses[size].checkbox,
                  colorSchemeClasses[colorScheme].checkbox,
                  'dark:border-gray-600 dark:bg-gray-700'
                )}
                aria-describedby={option.description ? `${optionId}-description` : undefined}
              />
              <div className="ml-3 flex-1 min-w-0">
                <div className={cn(
                  'font-medium',
                  sizeClasses[size].text,
                  isSelected ? 'text-primary-900 dark:text-primary-100' : 'text-gray-900 dark:text-gray-100'
                )}>
                  {option.icon && <span className="mr-2">{option.icon}</span>}
                  {option.label}
                </div>
                {option.description && (
                  <p
                    id={`${optionId}-description`}
                    className="text-sm text-gray-500 dark:text-gray-400 mt-1"
                  >
                    {option.description}
                  </p>
                )}
              </div>
            </label>
          );

        case 'button':
          return (
            <label
              key={option.value}
              htmlFor={optionId}
              className={cn(
                'relative inline-flex items-center justify-center px-4 py-2 border font-medium rounded-md cursor-pointer focus-within:ring-2 focus-within:ring-offset-2 transition-colors',
                isSelected
                  ? colorSchemeClasses[colorScheme].button
                  : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700',
                isDisabled && 'opacity-50 cursor-not-allowed',
                hasError && !isSelected && 'border-red-300 dark:border-red-600',
                sizeClasses[size].text,
                `focus-within:ring-${colorScheme}-500`
              )}
            >
              <input
                type="checkbox"
                id={optionId}
                name={groupId}
                value={option.value}
                checked={isSelected}
                onChange={() => handleOptionChange(option)}
                disabled={isDisabled}
                className="sr-only"
                aria-describedby={option.description ? `${optionId}-description` : undefined}
              />
              {option.icon && <span className="mr-2">{option.icon}</span>}
              {option.label}
            </label>
          );

        default:
          return (
            <label
              key={option.value}
              htmlFor={optionId}
              className={cn(
                'relative flex items-start cursor-pointer',
                isDisabled && 'opacity-50 cursor-not-allowed'
              )}
            >
              <input
                type="checkbox"
                id={optionId}
                name={groupId}
                value={option.value}
                checked={isSelected}
                onChange={() => handleOptionChange(option)}
                disabled={isDisabled}
                className={cn(
                  'mt-1 border-gray-300 rounded focus:ring-2 focus:ring-offset-2',
                  sizeClasses[size].checkbox,
                  colorSchemeClasses[colorScheme].checkbox,
                  'dark:border-gray-600 dark:bg-gray-700'
                )}
                aria-describedby={option.description ? `${optionId}-description` : undefined}
              />
              <div className="ml-3 flex-1 min-w-0">
                <div className={cn(
                  'font-medium',
                  sizeClasses[size].text,
                  'text-gray-900 dark:text-gray-100'
                )}>
                  {option.icon && <span className="mr-2">{option.icon}</span>}
                  {option.label}
                </div>
                {option.description && (
                  <p
                    id={`${optionId}-description`}
                    className="text-sm text-gray-500 dark:text-gray-400 mt-1"
                  >
                    {option.description}
                  </p>
                )}
              </div>
            </label>
          );
      }
    };

    return (
      <fieldset
        ref={ref}
        className={cn('space-y-2', className)}
        disabled={disabled}
        {...props}
      >
        {/* Legend/Label */}
        {label && (
          <legend className={cn(
            'text-sm font-medium mb-2',
            hasError ? 'text-red-700 dark:text-red-400' : 'text-gray-700 dark:text-gray-300'
          )}>
            {label}
            {required && <span className="text-red-500 ml-1">*</span>}
          </legend>
        )}

        {/* Description */}
        {description && (
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
            {description}
          </p>
        )}

        {/* Select All */}
        {showSelectAll && options.length > 0 && (
          <div className="mb-3 pb-3 border-b border-gray-200 dark:border-gray-700">
            <label
              htmlFor={`${groupId}-select-all`}
              className="relative flex items-center cursor-pointer"
            >
              <input
                type="checkbox"
                id={`${groupId}-select-all`}
                checked={allSelected}
                ref={(el) => {
                  if (el) el.indeterminate = isIndeterminate;
                }}
                onChange={handleSelectAll}
                disabled={disabled}
                className={cn(
                  'border-gray-300 rounded focus:ring-2 focus:ring-offset-2',
                  sizeClasses[size].checkbox,
                  colorSchemeClasses[colorScheme].checkbox,
                  'dark:border-gray-600 dark:bg-gray-700'
                )}
              />
              <div className="ml-3">
                <div className={cn(
                  'font-medium',
                  sizeClasses[size].text,
                  'text-gray-900 dark:text-gray-100'
                )}>
                  {allSelected ? 'Deselect All' : 'Select All'}
                </div>
                {maxSelections && (
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    {value.length}/{maxSelections} selected
                  </p>
                )}
              </div>
            </label>
          </div>
        )}

        {/* Options */}
        <div
          className={cn(
            orientation === 'vertical' ? 'space-y-0' : 'flex flex-wrap',
            spacingClasses[spacing]
          )}
          role="group"
          aria-labelledby={label ? `${groupId}-legend` : undefined}
        >
          {options.map((option, index) => renderCheckboxOption(option, index))}
        </div>

        {/* Selection Count */}
        {(maxSelections || minSelections > 0) && (
          <div className="text-xs text-gray-500 dark:text-gray-400 mt-2">
            {value.length} of {maxSelections || '∞'} selected
            {minSelections > 0 && ` (minimum ${minSelections})`}
          </div>
        )}

        {/* Helper Text */}
        {helperText && !error && (
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
            {helperText}
          </p>
        )}

        {/* Error Message */}
        {error && (
          <p className="text-sm text-red-600 dark:text-red-400 mt-2" role="alert">
            {error}
          </p>
        )}
      </fieldset>
    );
  }
);

CheckboxGroup.displayName = 'CheckboxGroup';

// Individual Checkbox Component
export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string;
  description?: string;
  size?: 'sm' | 'md' | 'lg';
  colorScheme?: 'primary' | 'secondary' | 'success' | 'warning' | 'danger';
  error?: boolean;
  indeterminate?: boolean;
}

export const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  ({
    label,
    description,
    size = 'md',
    colorScheme = 'primary',
    error = false,
    indeterminate = false,
    className,
    disabled,
    id,
    ...props
  }, ref) => {
    const checkboxId = id || `checkbox-${Math.random().toString(36).substr(2, 9)}`;
    const checkboxRef = React.useRef<HTMLInputElement>(null);

    // Combine refs
    React.useImperativeHandle(ref, () => checkboxRef.current!, []);

    // Set indeterminate state
    React.useEffect(() => {
      if (checkboxRef.current) {
        checkboxRef.current.indeterminate = indeterminate;
      }
    }, [indeterminate]);

    const sizeClasses = {
      sm: { checkbox: 'h-3 w-3', text: 'text-sm' },
      md: { checkbox: 'h-4 w-4', text: 'text-sm' },
      lg: { checkbox: 'h-5 w-5', text: 'text-base' }
    };

    const colorSchemeClasses = {
      primary: 'text-primary-600 focus:ring-primary-500',
      secondary: 'text-gray-600 focus:ring-gray-500',
      success: 'text-green-600 focus:ring-green-500',
      warning: 'text-yellow-600 focus:ring-yellow-500',
      danger: 'text-red-600 focus:ring-red-500'
    };

    return (
      <label
        htmlFor={checkboxId}
        className={cn(
          'relative flex items-start cursor-pointer',
          disabled && 'opacity-50 cursor-not-allowed',
          className
        )}
      >
        <input
          ref={checkboxRef}
          type="checkbox"
          id={checkboxId}
          className={cn(
            'mt-1 border-gray-300 rounded focus:ring-2 focus:ring-offset-2',
            sizeClasses[size].checkbox,
            colorSchemeClasses[colorScheme],
            error && 'border-red-500 focus:ring-red-500',
            'dark:border-gray-600 dark:bg-gray-700'
          )}
          disabled={disabled}
          aria-describedby={description ? `${checkboxId}-description` : undefined}
          {...props}
        />
        {(label || description) && (
          <div className="ml-3 flex-1 min-w-0">
            {label && (
              <div className={cn(
                'font-medium',
                sizeClasses[size].text,
                error ? 'text-red-700 dark:text-red-400' : 'text-gray-900 dark:text-gray-100'
              )}>
                {label}
              </div>
            )}
            {description && (
              <p
                id={`${checkboxId}-description`}
                className="text-sm text-gray-500 dark:text-gray-400 mt-1"
              >
                {description}
              </p>
            )}
          </div>
        )}
      </label>
    );
  }
);

Checkbox.displayName = 'Checkbox';

export type { CheckboxGroupProps, CheckboxProps, CheckboxOption };

/*
Usage Examples:

// Basic CheckboxGroup
<CheckboxGroup
  label="Interests"
  name="interests"
  value={selectedInterests}
  onChange={(values, options) => setSelectedInterests(values)}
  options={[
    { value: 'sports', label: 'Sports' },
    { value: 'music', label: 'Music' },
    { value: 'movies', label: 'Movies' },
    { value: 'reading', label: 'Reading' }
  ]}
/>

// Card variant with descriptions and icons
<CheckboxGroup
  label="Features"
  variant="card"
  colorScheme="primary"
  value={selectedFeatures}
  onChange={setSelectedFeatures}
  maxSelections={3}
  showSelectAll
  options={[
    {
      value: 'analytics',
      label: 'Advanced Analytics',
      description: 'Get detailed insights into your data with custom reports.',
      icon: '📊'
    },
    {
      value: 'api',
      label: 'API Access',
      description: 'Integrate with third-party services using our RESTful API.',
      icon: '🔌'
    },
    {
      value: 'support',
      label: 'Priority Support',
      description: '24/7 priority support with dedicated account manager.',
      icon: '🎧'
    }
  ]}
/>

// Button variant horizontal
<CheckboxGroup
  label="Tags"
  variant="button"
  orientation="horizontal"
  spacing="sm"
  value={selectedTags}
  onChange={setSelectedTags}
  options={[
    { value: 'urgent', label: 'Urgent' },
    { value: 'important', label: 'Important' },
    { value: 'bug', label: 'Bug' },
    { value: 'feature', label: 'Feature' },
    { value: 'documentation', label: 'Docs' }
  ]}
/>

// With min/max selections
<CheckboxGroup
  label="Skills (Select 2-5)"
  value={selectedSkills}
  onChange={setSelectedSkills}
  minSelections={2}
  maxSelections={5}
  showSelectAll
  error={selectedSkills.length < 2 ? "Please select at least 2 skills" : undefined}
  options={skillOptions}
/>

// Custom rendering
<CheckboxGroup
  label="Team Members"
  value={selectedMembers}
  onChange={setSelectedMembers}
  renderOption={(option, isSelected, isDisabled) => (
    <div className={cn(
      'flex items-center p-3 border rounded-lg',
      isSelected ? 'border-blue-500 bg-blue-50' : 'border-gray-200',
      isDisabled && 'opacity-50'
    )}>
      <img src={option.avatar} className="w-8 h-8 rounded-full mr-3" />
      <div className="flex-1">
        <div className="font-medium">{option.label}</div>
        <div className="text-sm text-gray-500">{option.email}</div>
      </div>
      {isSelected && <CheckIcon className="w-5 h-5 text-blue-500" />}
    </div>
  )}
  options={teamMembers}
/>

// Individual Checkbox
<Checkbox
  label="I agree to the terms and conditions"
  description="By checking this, you agree to our Terms of Service and Privacy Policy"
  required
  colorScheme="success"
/>

// Indeterminate checkbox
<Checkbox
  label="Select All Items"
  indeterminate={someItemsSelected && !allItemsSelected}
  checked={allItemsSelected}
  onChange={handleSelectAll}
/>

// Different sizes and colors
<CheckboxGroup size="lg" colorScheme="success" options={options} />
<CheckboxGroup size="sm" colorScheme="warning" variant="button" options={options} />
*/