import React from 'react';
import { cn } from '../../utils';

// Option interface
export interface SelectOption {
  value: string | number;
  label: string;
  disabled?: boolean;
  description?: string;
  icon?: React.ReactNode;
  group?: string;
}

// Select Component Props
export interface SelectProps extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'value' | 'onChange'> {
  options: SelectOption[];
  value?: string | number;
  onChange?: (value: string | number | undefined, option: SelectOption | undefined) => void;
  placeholder?: string;
  searchable?: boolean;
  clearable?: boolean;
  loading?: boolean;
  error?: string;
  helperText?: string;
  label?: string;
  required?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'filled' | 'flushed';
  maxHeight?: number;
  showGroups?: boolean;
  onSearch?: (query: string) => void;
  onClear?: () => void;
  onOpen?: () => void;
  onClose?: () => void;
  renderOption?: (option: SelectOption, isSelected: boolean) => React.ReactNode;
  renderValue?: (option: SelectOption | undefined) => React.ReactNode;
  noOptionsMessage?: string;
  loadingMessage?: string;
}

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({
    options = [],
    value,
    onChange,
    placeholder = 'Select an option...',
    searchable = false,
    clearable = false,
    loading = false,
    error,
    helperText,
    label,
    required = false,
    size = 'md',
    variant = 'default',
    maxHeight = 200,
    showGroups = true,
    onSearch,
    onClear,
    onOpen,
    onClose,
    renderOption,
    renderValue,
    noOptionsMessage = 'No options available',
    loadingMessage = 'Loading...',
    className,
    disabled,
    id,
    ...props
  }, ref) => {
    const [isOpen, setIsOpen] = React.useState(false);
    const [searchQuery, setSearchQuery] = React.useState('');
    const [focusedIndex, setFocusedIndex] = React.useState(-1);
    const [filteredOptions, setFilteredOptions] = React.useState<SelectOption[]>(options);

    const selectRef = React.useRef<HTMLDivElement>(null);
    const searchInputRef = React.useRef<HTMLInputElement>(null);
    const optionsRef = React.useRef<HTMLUListElement>(null);
    const selectId = id || `select-${Math.random().toString(36).substr(2, 9)}`;

    // Combine refs for native select fallback
    React.useImperativeHandle(ref, () => selectRef.current as any, []);

    // Find selected option
    const selectedOption = options.find(option => option.value === value);

    // Group options if showGroups is enabled
    const groupedOptions = React.useMemo(() => {
      if (!showGroups) return { '': filteredOptions };
      
      return filteredOptions.reduce((groups, option) => {
        const group = option.group || '';
        if (!groups[group]) groups[group] = [];
        groups[group].push(option);
        return groups;
      }, {} as Record<string, SelectOption[]>);
    }, [filteredOptions, showGroups]);

    // Filter options based on search query
    React.useEffect(() => {
      if (!searchQuery.trim()) {
        setFilteredOptions(options);
      } else {
        const filtered = options.filter(option =>
          option.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
          (option.description && option.description.toLowerCase().includes(searchQuery.toLowerCase()))
        );
        setFilteredOptions(filtered);
      }
      setFocusedIndex(-1);
    }, [searchQuery, options]);

    // Handle search
    const handleSearch = (query: string) => {
      setSearchQuery(query);
      onSearch?.(query);
    };

    // Handle option selection
    const handleOptionSelect = (option: SelectOption) => {
      if (option.disabled) return;
      
      onChange?.(option.value, option);
      setIsOpen(false);
      setSearchQuery('');
      setFocusedIndex(-1);
    };

    // Handle clear
    const handleClear = (e: React.MouseEvent) => {
      e.stopPropagation();
      onChange?.(undefined, undefined);
      onClear?.();
    };

    // Handle dropdown toggle
    const handleToggle = () => {
      if (disabled || loading) return;
      
      if (isOpen) {
        setIsOpen(false);
        onClose?.();
      } else {
        setIsOpen(true);
        onOpen?.();
        if (searchable) {
          setTimeout(() => searchInputRef.current?.focus(), 0);
        }
      }
    };

    // Handle keyboard navigation
    const handleKeyDown = (e: React.KeyboardEvent) => {
      if (!isOpen) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'ArrowDown') {
          e.preventDefault();
          handleToggle();
        }
        return;
      }

      switch (e.key) {
        case 'Escape':
          setIsOpen(false);
          onClose?.();
          break;
        
        case 'ArrowDown':
          e.preventDefault();
          setFocusedIndex(prev => {
            const nextIndex = prev < filteredOptions.length - 1 ? prev + 1 : 0;
            // Skip disabled options
            const nextOption = filteredOptions[nextIndex];
            return nextOption?.disabled ? nextIndex + 1 : nextIndex;
          });
          break;
        
        case 'ArrowUp':
          e.preventDefault();
          setFocusedIndex(prev => {
            const nextIndex = prev > 0 ? prev - 1 : filteredOptions.length - 1;
            // Skip disabled options
            const nextOption = filteredOptions[nextIndex];
            return nextOption?.disabled ? nextIndex - 1 : nextIndex;
          });
          break;
        
        case 'Enter':
          e.preventDefault();
          if (focusedIndex >= 0 && focusedIndex < filteredOptions.length) {
            handleOptionSelect(filteredOptions[focusedIndex]);
          }
          break;
      }
    };

    // Click outside handler
    React.useEffect(() => {
      const handleClickOutside = (event: MouseEvent) => {
        if (selectRef.current && !selectRef.current.contains(event.target as Node)) {
          setIsOpen(false);
          onClose?.();
        }
      };

      if (isOpen) {
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
      }
    }, [isOpen, onClose]);

    // Scroll focused option into view
    React.useEffect(() => {
      if (focusedIndex >= 0 && optionsRef.current) {
        const focusedElement = optionsRef.current.children[focusedIndex] as HTMLElement;
        if (focusedElement) {
          focusedElement.scrollIntoView({ block: 'nearest' });
        }
      }
    }, [focusedIndex]);

    const sizeClasses = {
      sm: 'h-8 px-3 text-sm',
      md: 'h-10 px-3 text-sm',
      lg: 'h-11 px-4 text-base'
    };

    const variantClasses = {
      default: 'border border-gray-300 bg-white focus:border-primary-500 focus:ring-primary-500 dark:border-gray-600 dark:bg-gray-800',
      filled: 'border-0 bg-gray-100 focus:bg-white focus:ring-2 focus:ring-primary-500 dark:bg-gray-700',
      flushed: 'border-0 border-b-2 border-gray-300 rounded-none bg-transparent focus:border-primary-500 focus:ring-0 dark:border-gray-600'
    };

    return (
      <div className="w-full">
        {/* Label */}
        {label && (
          <label
            htmlFor={selectId}
            className={cn(
              'block text-sm font-medium mb-1',
              error ? 'text-red-700 dark:text-red-400' : 'text-gray-700 dark:text-gray-300'
            )}
          >
            {label}
            {required && <span className="text-red-500 ml-1">*</span>}
          </label>
        )}

        {/* Select Container */}
        <div
          ref={selectRef}
          className="relative"
        >
          {/* Select Trigger */}
          <div
            className={cn(
              'w-full flex items-center justify-between cursor-pointer rounded-md transition-colors duration-200 focus:outline-none',
              sizeClasses[size],
              variantClasses[variant],
              error && 'border-red-500 focus:border-red-500 focus:ring-red-500',
              disabled && 'opacity-50 cursor-not-allowed bg-gray-50 dark:bg-gray-900',
              isOpen && 'ring-2 ring-primary-500 ring-opacity-20',
              className
            )}
            onClick={handleToggle}
            onKeyDown={handleKeyDown}
            role="combobox"
            aria-expanded={isOpen}
            aria-haspopup="listbox"
            aria-labelledby={label ? `${selectId}-label` : undefined}
            tabIndex={disabled ? -1 : 0}
          >
            {/* Selected Value */}
            <div className="flex-1 flex items-center min-w-0">
              {loading ? (
                <span className="text-gray-500">{loadingMessage}</span>
              ) : selectedOption ? (
                renderValue ? (
                  renderValue(selectedOption)
                ) : (
                  <div className="flex items-center">
                    {selectedOption.icon && (
                      <span className="mr-2 flex-shrink-0">{selectedOption.icon}</span>
                    )}
                    <span className="truncate">{selectedOption.label}</span>
                  </div>
                )
              ) : (
                <span className="text-gray-500 truncate">{placeholder}</span>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center ml-2 space-x-1">
              {clearable && selectedOption && !disabled && (
                <button
                  type="button"
                  onClick={handleClear}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 focus:outline-none"
                  tabIndex={-1}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              )}

              {loading ? (
                <svg className="animate-spin w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              ) : (
                <svg
                  className={cn(
                    'w-4 h-4 text-gray-400 transition-transform',
                    isOpen && 'rotate-180'
                  )}
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              )}
            </div>
          </div>

          {/* Dropdown */}
          {isOpen && (
            <div className="absolute z-50 w-full mt-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md shadow-lg">
              {/* Search Input */}
              {searchable && (
                <div className="p-2 border-b border-gray-200 dark:border-gray-700">
                  <input
                    ref={searchInputRef}
                    type="text"
                    value={searchQuery}
                    onChange={(e) => handleSearch(e.target.value)}
                    placeholder="Search options..."
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 dark:text-gray-100"
                  />
                </div>
              )}

              {/* Options List */}
              <ul
                ref={optionsRef}
                className="py-1 overflow-auto"
                style={{ maxHeight }}
                role="listbox"
              >
                {loading ? (
                  <li className="px-3 py-2 text-sm text-gray-500 text-center">
                    {loadingMessage}
                  </li>
                ) : filteredOptions.length === 0 ? (
                  <li className="px-3 py-2 text-sm text-gray-500 text-center">
                    {noOptionsMessage}
                  </li>
                ) : (
                  Object.entries(groupedOptions).map(([groupName, groupOptions]) => (
                    <React.Fragment key={groupName}>
                      {/* Group Header */}
                      {groupName && showGroups && (
                        <li className="px-3 py-1 text-xs font-semibold text-gray-500 uppercase bg-gray-50 dark:bg-gray-700">
                          {groupName}
                        </li>
                      )}

                      {/* Group Options */}
                      {groupOptions.map((option, index) => {
                        const globalIndex = filteredOptions.indexOf(option);
                        const isSelected = option.value === value;
                        const isFocused = globalIndex === focusedIndex;

                        return (
                          <li
                            key={option.value}
                            className={cn(
                              'px-3 py-2 cursor-pointer flex items-center text-sm',
                              isSelected && 'bg-primary-100 dark:bg-primary-900 text-primary-900 dark:text-primary-100',
                              isFocused && !isSelected && 'bg-gray-100 dark:bg-gray-700',
                              option.disabled && 'opacity-50 cursor-not-allowed',
                              !isSelected && !isFocused && 'text-gray-900 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700'
                            )}
                            onClick={() => handleOptionSelect(option)}
                            role="option"
                            aria-selected={isSelected}
                          >
                            {renderOption ? (
                              renderOption(option, isSelected)
                            ) : (
                              <>
                                {option.icon && (
                                  <span className="mr-3 flex-shrink-0">{option.icon}</span>
                                )}
                                <div className="flex-1 min-w-0">
                                  <div className="truncate">{option.label}</div>
                                  {option.description && (
                                    <div className="text-xs text-gray-500 dark:text-gray-400 truncate">
                                      {option.description}
                                    </div>
                                  )}
                                </div>
                                {isSelected && (
                                  <svg className="w-4 h-4 text-primary-600 dark:text-primary-400" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                                  </svg>
                                )}
                              </>
                            )}
                          </li>
                        );
                      })}
                    </React.Fragment>
                  ))
                )}
              </ul>
            </div>
          )}
        </div>

        {/* Helper Text */}
        {helperText && !error && (
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {helperText}
          </p>
        )}

        {/* Error Message */}
        {error && (
          <p className="mt-1 text-sm text-red-600 dark:text-red-400" role="alert">
            {error}
          </p>
        )}
      </div>
    );
  }
);

Select.displayName = 'Select';

export type { SelectProps, SelectOption };

/*
Usage Examples:

// Basic Select
<Select
  label="Country"
  placeholder="Select your country"
  options={[
    { value: 'us', label: 'United States' },
    { value: 'ca', label: 'Canada' },
    { value: 'uk', label: 'United Kingdom' }
  ]}
  onChange={(value, option) => console.log('Selected:', value, option)}
/>

// Searchable Select with groups
<Select
  label="Technology"
  searchable
  clearable
  showGroups
  options={[
    { value: 'react', label: 'React', group: 'Frontend', icon: '⚛️' },
    { value: 'vue', label: 'Vue.js', group: 'Frontend', icon: '💚' },
    { value: 'node', label: 'Node.js', group: 'Backend', icon: '🟢' },
    { value: 'python', label: 'Python', group: 'Backend', icon: '🐍' }
  ]}
  onSearch={(query) => console.log('Searching:', query)}
/>

// Custom option rendering
<Select
  label="Team Member"
  options={users}
  renderOption={(option, isSelected) => (
    <div className="flex items-center">
      <img 
        src={option.avatar} 
        alt={option.label}
        className="w-6 h-6 rounded-full mr-2"
      />
      <div>
        <div className="font-medium">{option.label}</div>
        <div className="text-xs text-gray-500">{option.email}</div>
      </div>
    </div>
  )}
  renderValue={(option) => (
    <div className="flex items-center">
      <img 
        src={option?.avatar} 
        alt={option?.label}
        className="w-5 h-5 rounded-full mr-2"
      />
      {option?.label}
    </div>
  )}
/>

// Loading state
<Select
  label="Remote Data"
  loading={isLoading}
  loadingMessage="Fetching options..."
  options={remoteOptions}
  onOpen={() => fetchOptions()}
/>

// Different sizes and variants
<Select size="sm" variant="filled" options={options} />
<Select size="lg" variant="flushed" options={options} />
*/