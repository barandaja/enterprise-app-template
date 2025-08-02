/**
 * Secure file upload component with validation and security checks
 */

import React, { useState, useRef } from 'react';
import { Upload, X, AlertCircle, CheckCircle } from 'lucide-react';
import { InputValidator } from '../security/inputValidation';
import { Button } from './Button';
import { Alert } from './Alert';
import { Spinner } from './Spinner';

export interface SecureFileUploadProps {
  accept?: string;
  maxSize?: number; // in bytes
  maxFiles?: number;
  allowedTypes?: string[];
  allowedExtensions?: string[];
  onUpload: (files: File[]) => Promise<void>;
  onError?: (error: string) => void;
  className?: string;
  disabled?: boolean;
  label?: string;
  helpText?: string;
  required?: boolean;
}

interface UploadedFile {
  file: File;
  id: string;
  status: 'pending' | 'uploading' | 'success' | 'error';
  error?: string;
  progress?: number;
}

export function SecureFileUpload({
  accept,
  maxSize = 10 * 1024 * 1024, // 10MB default
  maxFiles = 5,
  allowedTypes = [],
  allowedExtensions = [],
  onUpload,
  onError,
  className = '',
  disabled = false,
  label,
  helpText,
  required = false,
}: SecureFileUploadProps) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateFile = (file: File): { valid: boolean; error?: string } => {
    // Use the security validator
    const validation = InputValidator.validateFile(file, {
      maxSize,
      allowedTypes: allowedTypes.length > 0 ? allowedTypes : undefined,
      allowedExtensions: allowedExtensions.length > 0 ? allowedExtensions : undefined,
    });

    if (!validation.valid) {
      return validation;
    }

    // Additional security checks
    // Check for double extensions
    const fileName = file.name.toLowerCase();
    if (fileName.includes('..') || fileName.match(/\.(exe|bat|cmd|sh|ps1|vbs|js|jar|com|scr|msi|dll)$/)) {
      return { valid: false, error: 'Potentially dangerous file type' };
    }

    // Check MIME type consistency
    const extension = fileName.split('.').pop();
    if (extension) {
      const expectedTypes: Record<string, string[]> = {
        'jpg': ['image/jpeg'],
        'jpeg': ['image/jpeg'],
        'png': ['image/png'],
        'gif': ['image/gif'],
        'pdf': ['application/pdf'],
        'doc': ['application/msword'],
        'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
        'xls': ['application/vnd.ms-excel'],
        'xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
      };

      const expected = expectedTypes[extension];
      if (expected && !expected.includes(file.type)) {
        return { valid: false, error: 'File extension does not match file type' };
      }
    }

    return { valid: true };
  };

  const handleFileSelect = (selectedFiles: FileList | null) => {
    if (!selectedFiles || selectedFiles.length === 0) return;

    const newFiles: UploadedFile[] = [];
    const errors: string[] = [];

    // Check total file count
    if (files.length + selectedFiles.length > maxFiles) {
      errors.push(`Maximum ${maxFiles} files allowed`);
      onError?.(errors.join(', '));
      return;
    }

    Array.from(selectedFiles).forEach((file) => {
      const validation = validateFile(file);
      
      if (validation.valid) {
        newFiles.push({
          file,
          id: crypto.randomUUID(),
          status: 'pending',
        });
      } else {
        errors.push(`${file.name}: ${validation.error}`);
      }
    });

    if (errors.length > 0) {
      onError?.(errors.join(', '));
    }

    if (newFiles.length > 0) {
      setFiles((prev) => [...prev, ...newFiles]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) {
      setIsDragging(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (!disabled) {
      handleFileSelect(e.dataTransfer.files);
    }
  };

  const removeFile = (id: string) => {
    setFiles((prev) => prev.filter((f) => f.id !== id));
  };

  const uploadFiles = async () => {
    if (files.length === 0 || isUploading) return;

    setIsUploading(true);
    
    // Update all files to uploading status
    setFiles((prev) =>
      prev.map((f) => ({ ...f, status: 'uploading' as const }))
    );

    try {
      const validFiles = files.map((f) => f.file);
      await onUpload(validFiles);
      
      // Mark all as success
      setFiles((prev) =>
        prev.map((f) => ({ ...f, status: 'success' as const }))
      );
      
      // Clear successful files after a delay
      setTimeout(() => {
        setFiles([]);
      }, 2000);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Upload failed';
      setFiles((prev) =>
        prev.map((f) => ({
          ...f,
          status: 'error' as const,
          error: errorMessage,
        }))
      );
      onError?.(errorMessage);
    } finally {
      setIsUploading(false);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className={className}>
      {label && (
        <label className="block text-sm font-medium text-foreground mb-2">
          {label}
          {required && <span className="text-destructive ml-1">*</span>}
        </label>
      )}

      {/* Drop zone */}
      <div
        className={`relative rounded-lg border-2 border-dashed transition-colors ${
          isDragging
            ? 'border-primary bg-primary/5'
            : 'border-border hover:border-primary/50'
        } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !disabled && fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept={accept}
          multiple={maxFiles > 1}
          onChange={(e) => handleFileSelect(e.target.files)}
          className="hidden"
          disabled={disabled}
        />

        <div className="p-8 text-center">
          <Upload className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
          <p className="text-sm font-medium text-foreground mb-1">
            Drop files here or click to upload
          </p>
          <p className="text-xs text-muted-foreground">
            {allowedExtensions.length > 0
              ? `Accepted: ${allowedExtensions.map(ext => `.${ext}`).join(', ')}`
              : 'All file types accepted'}
            {` • Max ${formatFileSize(maxSize)} per file`}
          </p>
        </div>
      </div>

      {helpText && (
        <p className="mt-2 text-sm text-muted-foreground">{helpText}</p>
      )}

      {/* File list */}
      {files.length > 0 && (
        <div className="mt-4 space-y-2">
          {files.map((uploadedFile) => (
            <div
              key={uploadedFile.id}
              className={`flex items-center justify-between p-3 rounded-lg border ${
                uploadedFile.status === 'error'
                  ? 'border-destructive bg-destructive/5'
                  : uploadedFile.status === 'success'
                  ? 'border-green-500 bg-green-500/5'
                  : 'border-border bg-card'
              }`}
            >
              <div className="flex items-center space-x-3 flex-1 min-w-0">
                <div className="flex-shrink-0">
                  {uploadedFile.status === 'uploading' ? (
                    <Spinner size="sm" />
                  ) : uploadedFile.status === 'success' ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : uploadedFile.status === 'error' ? (
                    <AlertCircle className="h-5 w-5 text-destructive" />
                  ) : (
                    <Upload className="h-5 w-5 text-muted-foreground" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">
                    {uploadedFile.file.name}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {formatFileSize(uploadedFile.file.size)}
                    {uploadedFile.error && (
                      <span className="text-destructive ml-2">
                        • {uploadedFile.error}
                      </span>
                    )}
                  </p>
                </div>
              </div>
              {uploadedFile.status === 'pending' && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    removeFile(uploadedFile.id);
                  }}
                  className="ml-3 text-muted-foreground hover:text-foreground"
                  aria-label="Remove file"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Upload button */}
      {files.length > 0 && files.some((f) => f.status === 'pending') && (
        <div className="mt-4 flex justify-end">
          <Button
            onClick={uploadFiles}
            disabled={isUploading || disabled}
            loading={isUploading}
          >
            Upload {files.length} {files.length === 1 ? 'file' : 'files'}
          </Button>
        </div>
      )}
    </div>
  );
}