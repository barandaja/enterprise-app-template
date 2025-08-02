import React from 'react';
import { cn } from '../../utils';

// Column Definition
export interface Column<T = any> {
  key: string;
  title: string;
  dataIndex: keyof T;
  width?: number | string;
  minWidth?: number;
  maxWidth?: number;
  sortable?: boolean;
  filterable?: boolean;
  resizable?: boolean;
  fixed?: 'left' | 'right';
  align?: 'left' | 'center' | 'right';
  render?: (value: any, record: T, index: number) => React.ReactNode;
  renderHeader?: () => React.ReactNode;
  filterDropdown?: React.ReactNode;
  sorter?: boolean | ((a: T, b: T) => number);
  onHeaderCell?: () => React.HTMLAttributes<HTMLTableHeaderCellElement>;
  onCell?: (record: T, index: number) => React.HTMLAttributes<HTMLTableCellElement>;
}

// Sort State
export interface SortState {
  field: string;
  direction: 'asc' | 'desc';
}

// Filter State  
export interface FilterState {
  [key: string]: any;
}

// Selection State
export interface SelectionState<T = any> {
  selectedRowKeys: React.Key[];
  selectedRows: T[];
}

// DataTable Props
export interface DataTableProps<T = any> extends React.HTMLAttributes<HTMLDivElement> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  size?: 'sm' | 'md' | 'lg';
  bordered?: boolean;
  striped?: boolean;
  hover?: boolean;
  sticky?: boolean;
  scroll?: { x?: number | string; y?: number | string };
  
  // Row Props
  rowKey?: keyof T | ((record: T) => React.Key);
  rowSelection?: {
    type?: 'checkbox' | 'radio';
    selectedRowKeys?: React.Key[];
    onChange?: (selectedRowKeys: React.Key[], selectedRows: T[]) => void;
    onSelect?: (record: T, selected: boolean, selectedRows: T[]) => void;
    onSelectAll?: (selected: boolean, selectedRows: T[], changeRows: T[]) => void;
    getCheckboxProps?: (record: T) => { disabled?: boolean };
  };
  onRow?: (record: T, index: number) => React.HTMLAttributes<HTMLTableRowElement>;
  
  // Sorting
  sortable?: boolean;
  defaultSort?: SortState;
  onSort?: (sort: SortState | null) => void;
  
  // Filtering
  filterable?: boolean;
  filters?: FilterState;
  onFilter?: (filters: FilterState) => void;
  
  // Pagination
  pagination?: {
    current: number;
    pageSize: number;
    total: number;
    showSizeChanger?: boolean;
    showQuickJumper?: boolean;
    showTotal?: (total: number, range: [number, number]) => React.ReactNode;
    onChange?: (page: number, pageSize: number) => void;
  } | false;
  
  // Empty State
  emptyText?: React.ReactNode;
  
  // Expansion
  expandable?: {
    expandedRowKeys?: React.Key[];
    defaultExpandedRowKeys?: React.Key[];
    expandedRowRender?: (record: T, index: number) => React.ReactNode;
    expandIcon?: (props: { expanded: boolean; onExpand: () => void; record: T }) => React.ReactNode;
    onExpand?: (expanded: boolean, record: T) => void;
    rowExpandable?: (record: T) => boolean;
  };
  
  // Summary
  summary?: () => React.ReactNode;
}

export function DataTable<T extends Record<string, any>>({
  columns,
  data,
  loading = false,
  size = 'md',
  bordered = false,
  striped = false,
  hover = true,
  sticky = false,
  scroll,
  rowKey = 'id',
  rowSelection,
  onRow,
  sortable = false,
  defaultSort,
  onSort,
  filterable = false,
  filters,
  onFilter,
  pagination,
  emptyText = 'No data',
  expandable,
  summary,
  className,
  ...props
}: DataTableProps<T>) {
  const [sortState, setSortState] = React.useState<SortState | null>(defaultSort || null);
  const [filterState, setFilterState] = React.useState<FilterState>(filters || {});
  const [expandedKeys, setExpandedKeys] = React.useState<React.Key[]>(
    expandable?.defaultExpandedRowKeys || []
  );
  const [selectedKeys, setSelectedKeys] = React.useState<React.Key[]>(
    rowSelection?.selectedRowKeys || []
  );

  const tableRef = React.useRef<HTMLTableElement>(null);

  // Get row key
  const getRowKey = (record: T, index: number): React.Key => {
    if (typeof rowKey === 'function') {
      return rowKey(record);
    }
    return record[rowKey] ?? index;
  };

  // Handle sort
  const handleSort = (column: Column<T>) => {
    if (!column.sortable) return;

    let newSort: SortState | null = null;
    
    if (!sortState || sortState.field !== column.key) {
      newSort = { field: column.key, direction: 'asc' };
    } else if (sortState.direction === 'asc') {
      newSort = { field: column.key, direction: 'desc' };
    } else {
      newSort = null;
    }

    setSortState(newSort);
    onSort?.(newSort);
  };

  // Handle selection
  const handleRowSelect = (record: T, selected: boolean) => {
    const key = getRowKey(record, 0);
    let newSelectedKeys: React.Key[];
    
    if (rowSelection?.type === 'radio') {
      newSelectedKeys = selected ? [key] : [];
    } else {
      newSelectedKeys = selected
        ? [...selectedKeys, key]
        : selectedKeys.filter(k => k !== key);
    }
    
    setSelectedKeys(newSelectedKeys);
    const selectedRows = data.filter(item => 
      newSelectedKeys.includes(getRowKey(item, 0))
    );
    
    rowSelection?.onChange?.(newSelectedKeys, selectedRows);
    rowSelection?.onSelect?.(record, selected, selectedRows);
  };

  // Handle select all
  const handleSelectAll = (selected: boolean) => {
    const allKeys = data.map((item, index) => getRowKey(item, index));
    const newSelectedKeys = selected ? allKeys : [];
    
    setSelectedKeys(newSelectedKeys);
    const selectedRows = selected ? data : [];
    
    rowSelection?.onChange?.(newSelectedKeys, selectedRows);
    rowSelection?.onSelectAll?.(selected, selectedRows, data);
  };

  // Handle expand
  const handleExpand = (record: T, expanded: boolean) => {
    const key = getRowKey(record, 0);
    const newExpandedKeys = expanded
      ? [...expandedKeys, key]
      : expandedKeys.filter(k => k !== key);
    
    setExpandedKeys(newExpandedKeys);
    expandable?.onExpand?.(expanded, record);
  };

  const sizeClasses = {
    sm: 'text-xs',
    md: 'text-sm',
    lg: 'text-base'
  };

  const cellPaddingClasses = {
    sm: 'px-2 py-1',
    md: 'px-3 py-2',
    lg: 'px-4 py-3'
  };

  // Check if all rows are selected
  const allSelected = data.length > 0 && data.every((item, index) => 
    selectedKeys.includes(getRowKey(item, index))
  );
  const someSelected = selectedKeys.length > 0 && !allSelected;

  return (
    <div
      className={cn('relative overflow-hidden', className)}
      {...props}
    >
      {/* Loading Overlay */}
      {loading && (
        <div className="absolute inset-0 bg-white/80 dark:bg-gray-900/80 flex items-center justify-center z-10">
          <div className="flex items-center space-x-2">
            <svg className="animate-spin h-5 w-5 text-primary-600" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <span className="text-gray-600 dark:text-gray-400">Loading...</span>
          </div>
        </div>
      )}

      {/* Table Container */}
      <div
        className={cn(
          'overflow-auto',
          scroll?.x && 'overflow-x-auto',
          scroll?.y && 'overflow-y-auto'
        )}
        style={{
          maxHeight: scroll?.y,
          maxWidth: scroll?.x
        }}
      >
        <table
          ref={tableRef}
          className={cn(
            'w-full table-auto',
            sizeClasses[size],
            bordered && 'border border-gray-200 dark:border-gray-700'
          )}
        >
          {/* Table Header */}
          <thead
            className={cn(
              'bg-gray-50 dark:bg-gray-800',
              sticky && 'sticky top-0 z-20'
            )}
          >
            <tr>
              {/* Selection Column */}
              {rowSelection && (
                <th className={cn(
                  'text-left font-medium text-gray-900 dark:text-gray-100',
                  cellPaddingClasses[size],
                  bordered && 'border-r border-gray-200 dark:border-gray-700'
                )}>
                  {rowSelection.type !== 'radio' && (
                    <input
                      type="checkbox"
                      checked={allSelected}
                      ref={(el) => {
                        if (el) el.indeterminate = someSelected;
                      }}
                      onChange={(e) => handleSelectAll(e.target.checked)}
                      className="rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-gray-600 dark:bg-gray-700"
                    />
                  )}
                </th>
              )}

              {/* Expandable Column */}
              {expandable && (
                <th className={cn(
                  'w-12',
                  cellPaddingClasses[size],
                  bordered && 'border-r border-gray-200 dark:border-gray-700'
                )} />
              )}

              {/* Data Columns */}
              {columns.map((column) => (
                <th
                  key={column.key}
                  className={cn(
                    'font-medium text-gray-900 dark:text-gray-100',
                    cellPaddingClasses[size],
                    bordered && 'border-r border-gray-200 dark:border-gray-700',
                    column.align === 'center' && 'text-center',
                    column.align === 'right' && 'text-right',
                    column.sortable && 'cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 select-none'
                  )}
                  style={{
                    width: column.width,
                    minWidth: column.minWidth,
                    maxWidth: column.maxWidth
                  }}
                  onClick={() => column.sortable && handleSort(column)}
                  {...column.onHeaderCell?.()}
                >
                  <div className="flex items-center space-x-1">
                    {column.renderHeader ? column.renderHeader() : (
                      <span>{column.title}</span>
                    )}
                    
                    {column.sortable && (
                      <span className="flex flex-col">
                        <svg
                          className={cn(
                            'w-3 h-3 -mb-1',
                            sortState?.field === column.key && sortState.direction === 'asc'
                              ? 'text-primary-600'
                              : 'text-gray-400'
                          )}
                          fill="currentColor"
                          viewBox="0 0 20 20"
                        >
                          <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
                        </svg>
                        <svg
                          className={cn(
                            'w-3 h-3 rotate-180',
                            sortState?.field === column.key && sortState.direction === 'desc'
                              ? 'text-primary-600'
                              : 'text-gray-400'
                          )}
                          fill="currentColor"
                          viewBox="0 0 20 20"
                        >
                          <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
                        </svg>
                      </span>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>

          {/* Table Body */}
          <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
            {data.length === 0 ? (
              <tr>
                <td
                  colSpan={
                    columns.length + 
                    (rowSelection ? 1 : 0) + 
                    (expandable ? 1 : 0)
                  }
                  className={cn(
                    'text-center text-gray-500 dark:text-gray-400',
                    cellPaddingClasses[size]
                  )}
                >
                  {emptyText}
                </td>
              </tr>
            ) : (
              data.map((record, index) => {
                const key = getRowKey(record, index);
                const isSelected = selectedKeys.includes(key);
                const isExpanded = expandedKeys.includes(key);
                const canExpand = expandable?.rowExpandable?.(record) ?? true;

                return (
                  <React.Fragment key={key}>
                    {/* Main Row */}
                    <tr
                      className={cn(
                        striped && index % 2 === 1 && 'bg-gray-50 dark:bg-gray-800/50',
                        hover && 'hover:bg-gray-50 dark:hover:bg-gray-800/50',
                        isSelected && 'bg-primary-50 dark:bg-primary-900/20'
                      )}
                      {...onRow?.(record, index)}
                    >
                      {/* Selection Cell */}
                      {rowSelection && (
                        <td className={cn(
                          cellPaddingClasses[size],
                          bordered && 'border-r border-gray-200 dark:border-gray-700'
                        )}>
                          <input
                            type={rowSelection.type || 'checkbox'}
                            checked={isSelected}
                            onChange={(e) => handleRowSelect(record, e.target.checked)}
                            className="rounded border-gray-300 text-primary-600 focus:ring-primary-500 dark:border-gray-600 dark:bg-gray-700"
                            {...rowSelection.getCheckboxProps?.(record)}
                          />
                        </td>
                      )}

                      {/* Expand Cell */}
                      {expandable && (
                        <td className={cn(
                          cellPaddingClasses[size],
                          bordered && 'border-r border-gray-200 dark:border-gray-700'
                        )}>
                          {canExpand && (
                            <button
                              onClick={() => handleExpand(record, !isExpanded)}
                              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                            >
                              {expandable.expandIcon ? (
                                expandable.expandIcon({
                                  expanded: isExpanded,
                                  onExpand: () => handleExpand(record, !isExpanded),
                                  record
                                })
                              ) : (
                                <svg
                                  className={cn(
                                    'w-4 h-4 transition-transform',
                                    isExpanded && 'rotate-90'
                                  )}
                                  fill="none"
                                  viewBox="0 0 24 24"
                                  stroke="currentColor"
                                >
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                </svg>
                              )}
                            </button>
                          )}
                        </td>
                      )}

                      {/* Data Cells */}
                      {columns.map((column) => {
                        const value = record[column.dataIndex];
                        
                        return (
                          <td
                            key={column.key}
                            className={cn(
                              'text-gray-900 dark:text-gray-100',
                              cellPaddingClasses[size],
                              bordered && 'border-r border-gray-200 dark:border-gray-700',
                              column.align === 'center' && 'text-center',
                              column.align === 'right' && 'text-right'
                            )}
                            {...column.onCell?.(record, index)}
                          >
                            {column.render ? column.render(value, record, index) : String(value || '')}
                          </td>
                        );
                      })}
                    </tr>

                    {/* Expanded Row */}
                    {expandable && isExpanded && canExpand && (
                      <tr className="bg-gray-50 dark:bg-gray-800/50">
                        <td
                          colSpan={
                            columns.length + 
                            (rowSelection ? 1 : 0) + 
                            (expandable ? 1 : 0)
                          }
                          className={cellPaddingClasses[size]}
                        >
                          {expandable.expandedRowRender?.(record, index)}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>

          {/* Table Footer/Summary */}
          {summary && (
            <tfoot className="bg-gray-50 dark:bg-gray-800">
              {summary()}
            </tfoot>
          )}
        </table>
      </div>

      {/* Pagination */}
      {pagination && data.length > 0 && (
        <div className="flex items-center justify-between px-4 py-3 bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
          <div className="flex items-center text-sm text-gray-700 dark:text-gray-300">
            {pagination.showTotal?.(pagination.total, [
              (pagination.current - 1) * pagination.pageSize + 1,
              Math.min(pagination.current * pagination.pageSize, pagination.total)
            ])}
          </div>
          
          <div className="flex items-center space-x-2">
            {/* Pagination controls would go here */}
            <span className="text-sm text-gray-500 dark:text-gray-400">
              Page {pagination.current} of {Math.ceil(pagination.total / pagination.pageSize)}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

export type { DataTableProps, Column, SortState, FilterState, SelectionState };

/*
Usage Examples:

// Basic DataTable
<DataTable
  columns={[
    {
      key: 'name',
      title: 'Name',
      dataIndex: 'name',
      sortable: true
    },
    {
      key: 'email',
      title: 'Email',
      dataIndex: 'email',
      sortable: true
    },
    {
      key: 'status',
      title: 'Status',
      dataIndex: 'status',
      render: (status) => (
        <span className={`px-2 py-1 rounded text-xs ${
          status === 'active' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
        }`}>
          {status}
        </span>
      )
    }
  ]}
  data={users}
  loading={loading}
/>

// DataTable with selection and expansion
<DataTable
  columns={columns}
  data={data}
  rowSelection={{
    type: 'checkbox',
    selectedRowKeys,
    onChange: (keys, rows) => {
      setSelectedRowKeys(keys);
      setSelectedRows(rows);
    }
  }}
  expandable={{
    expandedRowRender: (record) => (
      <div className="p-4 bg-gray-50">
        <h4>Additional Details</h4>
        <p>{record.description}</p>
      </div>
    )
  }}
  pagination={{
    current: 1,
    pageSize: 10,
    total: 100,
    showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} items`
  }}
/>

// Scrollable DataTable
<DataTable
  columns={columns}
  data={data}
  scroll={{ x: 1200, y: 400 }}
  sticky
  bordered
/>
*/