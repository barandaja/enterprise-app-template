import React from 'react';
import { cn } from '../../utils';
import { SelectOption } from './Select';

// MultiSelect Component Props
export interface MultiSelectProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'value' | 'onChange'> {
  options: SelectOption[];
  value?: (string | number)[];
  onChange?: (values: (string | number)[], selectedOptions: SelectOption[]) => void;
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
  maxSelections?: number;
  showSelectAll?: boolean;
  showSelectedCount?: boolean;
  closeOnSelect?: boolean;
  onSearch?: (query: string) => void;
  onClear?: () => void;
  onOpen?: () => void;
  onClose?: () => void;
  onSelectAll?: () => void;
  onDeselectAll?: () => void;
  renderOption?: (option: SelectOption, isSelected: boolean) => React.ReactNode;
  renderTag?: (option: SelectOption, onRemove: () => void) => React.ReactNode;
  noOptionsMessage?: string;
  loadingMessage?: string;
  maxTagsToShow?: number;
  tagVariant?: 'default' | 'solid' | 'outline';
}

export const MultiSelect = React.forwardRef<HTMLDivElement, MultiSelectProps>(
  ({
    options = [],
    value = [],
    onChange,
    placeholder = 'Select options...',
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
    maxSelections,
    showSelectAll = false,
    showSelectedCount = false,
    closeOnSelect = false,
    onSearch,
    onClear,
    onOpen,
    onClose,
    onSelectAll,
    onDeselectAll,
    renderOption,
    renderTag,
    noOptionsMessage = 'No options available',
    loadingMessage = 'Loading...',
    maxTagsToShow = 3,
    tagVariant = 'default',
    className,
    id,
    ...props
  }, ref) => {
    const [isOpen, setIsOpen] = React.useState(false);
    const [searchQuery, setSearchQuery] = React.useState('');
    const [focusedIndex, setFocusedIndex] = React.useState(-1);
    const [filteredOptions, setFilteredOptions] = React.useState<SelectOption[]>(options);

    const containerRef = React.useRef<HTMLDivElement>(null);
    const searchInputRef = React.useRef<HTMLInputElement>(null);
    const optionsRef = React.useRef<HTMLUListElement>(null);
    const selectId = id || `multiselect-${Math.random().toString(36).substr(2, 9)}`;

    // Combine refs
    React.useImperativeHandle(ref, () => containerRef.current!, []);

    // Find selected options
    const selectedOptions = options.filter(option => value.includes(option.value));
    const canSelectMore = !maxSelections || value.length < maxSelections;

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
    const handleOptionToggle = (option: SelectOption) => {
      if (option.disabled) return;
      
      const isSelected = value.includes(option.value);
      let newValues: (string | number)[];
      
      if (isSelected) {
        // Remove option
        newValues = value.filter(v => v !== option.value);
      } else {
        // Add option (if within limit)
        if (!canSelectMore) return;
        newValues = [...value, option.value];
      }
      
      const newSelectedOptions = options.filter(opt => newValues.includes(opt.value));
      onChange?.(newValues, newSelectedOptions);
      
      if (closeOnSelect && !isSelected) {
        setIsOpen(false);
        onClose?.();
      }
    };

    // Handle tag removal
    const handleTagRemove = (optionValue: string | number) => {
      const newValues = value.filter(v => v !== optionValue);
      const newSelectedOptions = options.filter(opt => newValues.includes(opt.value));
      onChange?.(newValues, newSelectedOptions);
    };

    // Handle select all
    const handleSelectAll = () => {
      const availableOptions = filteredOptions.filter(opt => !opt.disabled);
      const allValues = availableOptions.map(opt => opt.value);
      
      // Respect maxSelections limit
      const finalValues = maxSelections 
        ? allValues.slice(0, maxSelections)
        : allValues;
      
      const finalSelectedOptions = options.filter(opt => finalValues.includes(opt.value));
      onChange?.(finalValues, finalSelectedOptions);
      onSelectAll?.();
    };

    // Handle deselect all
    const handleDeselectAll = () => {
      onChange?.([], []);
      onDeselectAll?.();
    };

    // Handle clear
    const handleClear = (e: React.MouseEvent) => {
      e.stopPropagation();
      onChange?.([], []);
      onClear?.();
    };

    // Handle dropdown toggle
    const handleToggle = () => {
      if (loading) return;
      
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
            const nextOption = filteredOptions[nextIndex];
            return nextOption?.disabled ? nextIndex + 1 : nextIndex;
          });
          break;
        
        case 'ArrowUp':
          e.preventDefault();
          setFocusedIndex(prev => {
            const nextIndex = prev > 0 ? prev - 1 : filteredOptions.length - 1;
            const nextOption = filteredOptions[nextIndex];
            return nextOption?.disabled ? nextIndex - 1 : nextIndex;
          });
          break;
        
        case 'Enter':
          e.preventDefault();
          if (focusedIndex >= 0 && focusedIndex < filteredOptions.length) {
            handleOptionToggle(filteredOptions[focusedIndex]);
          }
          break;
      }
    };

    // Click outside handler
    React.useEffect(() => {
      const handleClickOutside = (event: MouseEvent) => {
        if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
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
      sm: 'min-h-8 px-3 text-sm',
      md: 'min-h-10 px-3 text-sm',
      lg: 'min-h-11 px-4 text-base'
    };

    const variantClasses = {
      default: 'border border-gray-300 bg-white focus-within:border-primary-500 focus-within:ring-primary-500 dark:border-gray-600 dark:bg-gray-800',
      filled: 'border-0 bg-gray-100 focus-within:bg-white focus-within:ring-2 focus-within:ring-primary-500 dark:bg-gray-700',
      flushed: 'border-0 border-b-2 border-gray-300 rounded-none bg-transparent focus-within:border-primary-500 focus-within:ring-0 dark:border-gray-600'
    };

    const tagVariantClasses = {
      default: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
      solid: 'bg-primary-100 text-primary-800 dark:bg-primary-900 dark:text-primary-200',
      outline: 'border border-gray-300 bg-white text-gray-700 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-300'
    };

    // Render tags
    const renderTags = () => {
      const tagsToShow = selectedOptions.slice(0, maxTagsToShow);
      const hiddenCount = selectedOptions.length - maxTagsToShow;

      return (
        <div className="flex flex-wrap gap-1 min-w-0">
          {tagsToShow.map((option) => (
            <span
              key={option.value}
              className={cn(
                'inline-flex items-center px-2 py-1 rounded text-xs font-medium',
                tagVariantClasses[tagVariant]
              )}
            >
              {renderTag ? (
                renderTag(option, () => handleTagRemove(option.value))
              ) : (
                <>
                  {option.icon && <span className="mr-1">{option.icon}</span>}
                  <span className="truncate max-w-24">{option.label}</span>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleTagRemove(option.value);
                    }}
                    className="ml-1 text-current hover:text-red-600 focus:outline-none"
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </>
              )}
            </span>
          ))}
          
          {hiddenCount > 0 && (
            <span className={cn(
              'inline-flex items-center px-2 py-1 rounded text-xs font-medium',
              tagVariantClasses[tagVariant]
            )}>
              +{hiddenCount} more
            </span>
          )}
        </div>
      );
    };

    const allSelectableSelected = filteredOptions
      .filter(opt => !opt.disabled)
      .every(opt => value.includes(opt.value));

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

        {/* MultiSelect Container */}
        <div
          ref={containerRef}
          className="relative"
          {...props}
        >
          {/* Select Trigger */}
          <div
            className={cn(
              'w-full flex items-center justify-between cursor-pointer rounded-md transition-colors duration-200 focus:outline-none py-2',
              sizeClasses[size],
              variantClasses[variant],
              error && 'border-red-500 focus-within:border-red-500 focus-within:ring-red-500',
              loading && 'opacity-50 cursor-not-allowed',
              isOpen && 'ring-2 ring-primary-500 ring-opacity-20',
              className
            )}
            onClick={handleToggle}
            onKeyDown={handleKeyDown}
            role="combobox"
            aria-expanded={isOpen}
            aria-haspopup="listbox"
            aria-labelledby={label ? `${selectId}-label` : undefined}
            tabIndex={loading ? -1 : 0}
          >
            {/* Selected Values */}
            <div className="flex-1 flex items-center min-w-0">
              {loading ? (
                <span className="text-gray-500">{loadingMessage}</span>
              ) : selectedOptions.length > 0 ? (
                showSelectedCount ? (
                  <span className="text-gray-900 dark:text-gray-100">
                    {selectedOptions.length} selected
                  </span>
                ) : (
                  renderTags()
                )
              ) : (
                <span className="text-gray-500 truncate">{placeholder}</span>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center ml-2 space-x-1 flex-shrink-0">
              {clearable && selectedOptions.length > 0 && !loading && (
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
              {/* Header with Search and Select All */}
              <div className="p-2 border-b border-gray-200 dark:border-gray-700 space-y-2">
                {/* Search Input */}
                {searchable && (
                  <input
                    ref={searchInputRef}
                    type="text"
                    value={searchQuery}
                    onChange={(e) => handleSearch(e.target.value)}
                    placeholder="Search options..."
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 dark:bg-gray-700 dark:text-gray-100"
                  />
                )}

                {/* Select All / Deselect All */}
                {showSelectAll && filteredOptions.length > 0 && (
                  <div className="flex items-center justify-between">
                    <button
                      type="button"
                      onClick={allSelectableSelected ? handleDeselectAll : handleSelectAll}
                      className="text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 focus:outline-none"
                      disabled={!canSelectMore && !allSelectableSelected}
                    >
                      {allSelectableSelected ? 'Deselect All' : 'Select All'}
                    </button>
                    
                    {maxSelections && (
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        {value.length}/{maxSelections} selected
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Options List */}
              <ul
                ref={optionsRef}
                className="py-1 overflow-auto"
                style={{ maxHeight }}
                role="listbox"
                aria-multiselectable="true"
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
                        const isSelected = value.includes(option.value);
                        const isFocused = globalIndex === focusedIndex;
                        const canSelect = canSelectMore || isSelected;

                        return (
                          <li
                            key={option.value}
                            className={cn(
                              'px-3 py-2 cursor-pointer flex items-center text-sm',
                              isSelected && 'bg-primary-100 dark:bg-primary-900',
                              isFocused && !isSelected && 'bg-gray-100 dark:bg-gray-700',
                              option.disabled && 'opacity-50 cursor-not-allowed',
                              !canSelect && !isSelected && 'opacity-50 cursor-not-allowed',
                              !isSelected && !isFocused && 'text-gray-900 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700'
                            )}
                            onClick={() => handleOptionToggle(option)}
                            role="option"
                            aria-selected={isSelected}
                          >
                            {/* Checkbox */}
                            <div className="mr-3 flex-shrink-0">
                              <div className={cn(
                                'w-4 h-4 border-2 rounded flex items-center justify-center',
                                isSelected 
                                  ? 'bg-primary-600 border-primary-600 text-white'
                                  : 'border-gray-300 dark:border-gray-600'
                              )}>
                                {isSelected && (
                                  <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                                  </svg>
                                )}
                              </div>
                            </div>

                            {/* Option Content */}
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

MultiSelect.displayName = 'MultiSelect';

export type { MultiSelectProps };

/*
Usage Examples:

// Basic MultiSelect
<MultiSelect
  label="Skills"
  placeholder="Select your skills"
  options={[
    { value: 'js', label: 'JavaScript' },
    { value: 'ts', label: 'TypeScript' },
    { value: 'react', label: 'React' },
    { value: 'vue', label: 'Vue.js' }
  ]}
  value={selectedSkills}
  onChange={(values, options) => setSelectedSkills(values)}
/>

// Searchable with groups and limits
<MultiSelect
  label="Technologies"
  searchable
  clearable
  showSelectAll
  showGroups
  maxSelections={5}
  options={[
    { value: 'react', label: 'React', group: 'Frontend', icon: '⚛️' },
    { value: 'vue', label: 'Vue.js', group: 'Frontend', icon: '💚' },
    { value: 'node', label: 'Node.js', group: 'Backend', icon: '🟢' },
    { value: 'python', label: 'Python', group: 'Backend', icon: '🐍' }
  ]}
  onSelectAll={() => console.log('Selected all')}
  onDeselectAll={() => console.log('Deselected all')}
/>

// Custom tag rendering
<MultiSelect
  label="Team Members"
  options={teamMembers}
  value={selectedMembers}
  onChange={setSelectedMembers}
  tagVariant="solid"
  maxTagsToShow={2}
  renderTag={(option, onRemove) => (
    <div className="flex items-center bg-blue-100 text-blue-800 px-2 py-1 rounded">
      <img src={option.avatar} className="w-4 h-4 rounded-full mr-1" />
      {option.label}
      <button onClick={onRemove} className="ml-1 hover:text-red-600">×</button>
    </div>
  )}
/>

// Show selected count instead of tags
<MultiSelect
  label="Categories"
  options={categories}
  value={selectedCategories}
  onChange={setSelectedCategories}
  showSelectedCount
  closeOnSelect={false}
  maxSelections={10}
/>

// Different variants and sizes
<MultiSelect size="sm" variant="filled" options={options} />
<MultiSelect size="lg" variant="flushed" options={options} />
*/