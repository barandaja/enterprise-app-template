import React from 'react';
import { cn } from '../../utils';

export interface FieldArrayItem {
  id: string;
  [key: string]: any;
}

export interface FieldArrayProps<T extends FieldArrayItem> {
  items: T[];
  onChange: (items: T[]) => void;
  renderItem: (item: T, index: number, actions: FieldArrayActions<T>) => React.ReactNode;
  createNewItem: () => T;
  maxItems?: number;
  minItems?: number;
  addButtonText?: string;
  removeButtonText?: string;
  emptyStateText?: string;
  emptyStateIcon?: React.ReactNode;
  showAddButton?: boolean;
  showRemoveButton?: boolean; 
  allowReorder?: boolean;
  disabled?: boolean;
  label?: string;
  description?: string;
  error?: string;
  className?: string;
  itemClassName?: string;
  addButtonClassName?: string;
  onAdd?: (item: T) => void;
  onRemove?: (item: T, index: number) => void;
  onReorder?: (fromIndex: number, toIndex: number) => void;
  validate?: (items: T[]) => string | undefined;
  sortable?: boolean;
  collapsible?: boolean;
}

export interface FieldArrayActions<T extends FieldArrayItem> {
  remove: () => void;
  moveUp: () => void;
  moveDown: () => void;
  duplicate: () => void;
  update: (updates: Partial<T>) => void;
}

export function FieldArray<T extends FieldArrayItem>({
  items,
  onChange,
  renderItem,
  createNewItem,
  maxItems,
  minItems = 0,
  addButtonText = 'Add Item',
  removeButtonText = 'Remove',
  emptyStateText = 'No items added yet.',
  emptyStateIcon,
  showAddButton = true,
  showRemoveButton = true,
  allowReorder = false,
  disabled = false,
  label,
  description,
  error,
  className,
  itemClassName,
  addButtonClassName,
  onAdd,
  onRemove,
  onReorder,
  validate,
  sortable = false,
  collapsible = false
}: FieldArrayProps<T>) {
  const [draggedIndex, setDraggedIndex] = React.useState<number | null>(null);
  const [dragOverIndex, setDragOverIndex] = React.useState<number | null>(null);
  const [collapsedItems, setCollapsedItems] = React.useState<Set<number>>(new Set());

  const canAddMore = !maxItems || items.length < maxItems;
  const canRemove = items.length > minItems;
  const validationError = validate ? validate(items) : undefined;
  const displayError = error || validationError;

  // Generate new item ID
  const generateId = () => `item-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

  // Add new item
  const handleAdd = () => {
    if (!canAddMore || disabled) return;
    
    const newItem = createNewItem();
    // Ensure the new item has an ID
    if (!newItem.id) {
      newItem.id = generateId();
    }
    
    const newItems = [...items, newItem];
    onChange(newItems);
    onAdd?.(newItem);
  };

  // Remove item
  const handleRemove = (index: number) => {
    if (!canRemove || disabled) return;
    
    const itemToRemove = items[index];
    const newItems = items.filter((_, i) => i !== index);
    onChange(newItems);
    onRemove?.(itemToRemove, index);
  };

  // Move item up
  const handleMoveUp = (index: number) => {
    if (index === 0 || disabled) return;
    
    const newItems = [...items];
    [newItems[index - 1], newItems[index]] = [newItems[index], newItems[index - 1]];
    onChange(newItems);
    onReorder?.(index, index - 1);
  };

  // Move item down
  const handleMoveDown = (index: number) => {
    if (index === items.length - 1 || disabled) return;
    
    const newItems = [...items];
    [newItems[index], newItems[index + 1]] = [newItems[index + 1], newItems[index]];
    onChange(newItems);
    onReorder?.(index, index + 1);
  };

  // Duplicate item
  const handleDuplicate = (index: number) => {
    if (!canAddMore || disabled) return;
    
    const itemToDuplicate = items[index];
    const duplicatedItem = {
      ...itemToDuplicate,
      id: generateId()
    };
    
    const newItems = [
      ...items.slice(0, index + 1),
      duplicatedItem,
      ...items.slice(index + 1)
    ];
    onChange(newItems);
  };

  // Update item
  const handleUpdate = (index: number, updates: Partial<T>) => {
    if (disabled) return;
    
    const newItems = items.map((item, i) => 
      i === index ? { ...item, ...updates } : item
    );
    onChange(newItems);
  };

  // Toggle collapse state
  const handleToggleCollapse = (index: number) => {
    const newCollapsedItems = new Set(collapsedItems);
    if (newCollapsedItems.has(index)) {
      newCollapsedItems.delete(index);
    } else {
      newCollapsedItems.add(index);
    }
    setCollapsedItems(newCollapsedItems);
  };

  // Drag and drop handlers
  const handleDragStart = (e: React.DragEvent, index: number) => {
    if (!sortable || disabled) return;
    setDraggedIndex(index);
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/html', e.currentTarget.outerHTML);
  };

  const handleDragOver = (e: React.DragEvent, index: number) => {
    if (!sortable || disabled) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDragOverIndex(index);
  };

  const handleDragLeave = () => {
    setDragOverIndex(null);
  };

  const handleDrop = (e: React.DragEvent, dropIndex: number) => {
    if (!sortable || disabled || draggedIndex === null) return;
    
    e.preventDefault();
    
    if (draggedIndex !== dropIndex) {
      const newItems = [...items];
      const draggedItem = newItems[draggedIndex];
      
      // Remove dragged item
      newItems.splice(draggedIndex, 1);
      
      // Insert at new position
      const insertIndex = draggedIndex < dropIndex ? dropIndex - 1 : dropIndex;
      newItems.splice(insertIndex, 0, draggedItem);
      
      onChange(newItems);
      onReorder?.(draggedIndex, insertIndex);
    }
    
    setDraggedIndex(null);
    setDragOverIndex(null);
  };

  const handleDragEnd = () => {
    setDraggedIndex(null);
    setDragOverIndex(null);
  };

  // Create actions for each item
  const createActions = (index: number): FieldArrayActions<T> => ({
    remove: () => handleRemove(index),
    moveUp: () => handleMoveUp(index),
    moveDown: () => handleMoveDown(index),
    duplicate: () => handleDuplicate(index),
    update: (updates: Partial<T>) => handleUpdate(index, updates)
  });

  return (
    <div className={cn('space-y-4', className)}>
      {/* Label and Description */}
      {(label || description) && (
        <div className="space-y-1">
          {label && (
            <label className={cn(
              'block text-sm font-medium',
              displayError ? 'text-red-700 dark:text-red-400' : 'text-gray-700 dark:text-gray-300'
            )}>
              {label}
            </label>
          )}
          {description && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {description}
            </p>
          )}
        </div>
      )}

      {/* Items List */}
      <div className="space-y-3">
        {items.length === 0 ? (
          // Empty State
          <div className="text-center py-8 px-4 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg">
            {emptyStateIcon && (
              <div className="flex justify-center mb-2 text-gray-400">
                {emptyStateIcon}
              </div>
            )}
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {emptyStateText}
            </p>
          </div>
        ) : (
          items.map((item, index) => {
            const isCollapsed = collapsible && collapsedItems.has(index);
            const isDragging = draggedIndex === index;
            const isDragOver = dragOverIndex === index;
            
            return (
              <div
                key={item.id}
                className={cn(
                  'relative border border-gray-200 dark:border-gray-700 rounded-lg',
                  isDragging && 'opacity-50',
                  isDragOver && 'border-primary-500 bg-primary-50 dark:bg-primary-900/20',
                  itemClassName
                )}
                draggable={sortable && !disabled}
                onDragStart={(e) => handleDragStart(e, index)}
                onDragOver={(e) => handleDragOver(e, index)}
                onDragLeave={handleDragLeave}
                onDrop={(e) => handleDrop(e, index)}
                onDragEnd={handleDragEnd}
              >
                {/* Item Header */}
                <div className="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center space-x-2">
                    {/* Drag Handle */}
                    {sortable && !disabled && (
                      <div className="cursor-move text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                          <path d="M7 2a2 2 0 1 1 .001 3.999A2 2 0 0 1 7 2zM7 8a2 2 0 1 1 .001 3.999A2 2 0 0 1 7 8zM7 14a2 2 0 1 1 .001 3.999A2 2 0 0 1 7 14zM13 2a2 2 0 1 1 .001 3.999A2 2 0 0 1 13 2zM13 8a2 2 0 1 1 .001 3.999A2 2 0 0 1 13 8zM13 14a2 2 0 1 1 .001 3.999A2 2 0 0 1 13 14z"/>
                        </svg>
                      </div>
                    )}

                    <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                      Item {index + 1}
                    </span>

                    {/* Collapse Toggle */}
                    {collapsible && (
                      <button
                        type="button"
                        onClick={() => handleToggleCollapse(index)}
                        className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                        disabled={disabled}
                      >
                        <svg
                          className={cn('w-4 h-4 transition-transform', isCollapsed && 'rotate-180')}
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center space-x-1">
                    {/* Move Up */}
                    {allowReorder && index > 0 && (
                      <button
                        type="button"
                        onClick={() => handleMoveUp(index)}
                        className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50"
                        disabled={disabled}
                        title="Move up"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                        </svg>
                      </button>
                    )}

                    {/* Move Down */}
                    {allowReorder && index < items.length - 1 && (
                      <button
                        type="button"
                        onClick={() => handleMoveDown(index)}
                        className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50"
                        disabled={disabled}
                        title="Move down"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                    )}

                    {/* Duplicate */}
                    {canAddMore && (
                      <button
                        type="button"
                        onClick={() => handleDuplicate(index)}
                        className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:opacity-50"
                        disabled={disabled}
                        title="Duplicate"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    )}

                    {/* Remove */}
                    {showRemoveButton && canRemove && (
                      <button
                        type="button"
                        onClick={() => handleRemove(index)}
                        className="p-1 text-red-400 hover:text-red-600 dark:hover:text-red-300 disabled:opacity-50"
                        disabled={disabled}
                        title={removeButtonText}
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    )}
                  </div>
                </div>

                {/* Item Content */}
                {(!collapsible || !isCollapsed) && (
                  <div className="p-3">
                    {renderItem(item, index, createActions(index))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Add Button */}
      {showAddButton && canAddMore && (
        <button
          type="button"
          onClick={handleAdd}
          className={cn(
            'w-full flex items-center justify-center px-4 py-2 border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 hover:border-gray-400 dark:hover:border-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed',
            addButtonClassName
          )}
          disabled={disabled}
        >
          <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          {addButtonText}
        </button>
      )}

      {/* Error Message */}
      {displayError && (
        <p className="text-sm text-red-600 dark:text-red-400" role="alert">
          {displayError}
        </p>
      )}

      {/* Item Count */}
      {(minItems > 0 || maxItems) && (
        <p className="text-xs text-gray-500 dark:text-gray-400">
          {items.length} of {maxItems || '∞'} items
          {minItems > 0 && ` (minimum ${minItems})`}
        </p>
      )}
    </div>
  );
}

export type { FieldArrayProps, FieldArrayActions, FieldArrayItem };

/*
Usage Examples:

// Basic usage with simple items
interface ContactItem extends FieldArrayItem {
  name: string;
  email: string;
  phone: string;
}

<FieldArray<ContactItem>
  items={contacts}
  onChange={setContacts}
  createNewItem={() => ({
    id: '',
    name: '',
    email: '',
    phone: ''
  })}
  renderItem={(item, index, actions) => (
    <div className="space-y-4">
      <FormField label="Name">
        <Input 
          value={item.name}
          onChange={(e) => actions.update({ name: e.target.value })}
        />
      </FormField>
      <FormField label="Email">
        <Input 
          type="email"
          value={item.email}
          onChange={(e) => actions.update({ email: e.target.value })}
        />
      </FormField>
      <FormField label="Phone">
        <Input 
          type="tel"
          value={item.phone}
          onChange={(e) => actions.update({ phone: e.target.value })}
        />
      </FormField>
    </div>
  )}
  label="Emergency Contacts"
  description="Add people we can contact in case of emergency"
  maxItems={5}
  minItems={1}
  allowReorder
  sortable
  collapsible
  validate={(items) => {
    if (items.length === 0) return "At least one contact is required";
    const hasInvalidItems = items.some(item => !item.name || !item.email);
    if (hasInvalidItems) return "All contacts must have a name and email";
  }}
/>

// With custom empty state
<FieldArray
  items={items}
  onChange={setItems}
  createNewItem={() => ({ id: '', value: '' })}
  renderItem={(item, index, actions) => (
    <Input 
      value={item.value}
      onChange={(e) => actions.update({ value: e.target.value })}
    />
  )}
  emptyStateText="No items yet. Click the button below to add your first item."
  emptyStateIcon={<PlusIcon className="w-8 h-8" />}
  addButtonText="Add New Item"
  addButtonClassName="border-primary-300 text-primary-700 hover:bg-primary-50"
/>

// Advanced usage with custom actions
<FieldArray
  items={formSections}
  onChange={setFormSections}
  createNewItem={() => ({
    id: '',
    title: '',
    fields: []
  })}
  renderItem={(section, index, actions) => (
    <div>
      <FormField label="Section Title">
        <Input 
          value={section.title}
          onChange={(e) => actions.update({ title: e.target.value })}
        />
      </FormField>
      
      <FieldArray
        items={section.fields}
        onChange={(fields) => actions.update({ fields })}
        createNewItem={() => ({ id: '', name: '', type: 'text' })}
        renderItem={(field, fieldIndex, fieldActions) => (
          <div className="flex gap-2">
            <Input 
              placeholder="Field name"
              value={field.name}
              onChange={(e) => fieldActions.update({ name: e.target.value })}
            />
            <select 
              value={field.type}
              onChange={(e) => fieldActions.update({ type: e.target.value })}
            >
              <option value="text">Text</option>
              <option value="email">Email</option>
              <option value="number">Number</option>
            </select>
          </div>
        )}
        label="Fields"
        addButtonText="Add Field"
      />
    </div>
  )}
  label="Form Sections"
  showAddButton={true}
  showRemoveButton={true}
  allowReorder={true}
  onAdd={(item) => console.log('Added:', item)}
  onRemove={(item, index) => console.log('Removed:', item, 'at index', index)}
  onReorder={(from, to) => console.log('Reordered from', from, 'to', to)}
/>
*/