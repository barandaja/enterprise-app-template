# SecureFileUpload Component

## Overview

The `SecureFileUpload` component provides a secure file upload interface with comprehensive client-side validation and security checks. This component is designed to prevent common file upload vulnerabilities while providing a user-friendly experience.

## Security Features

### Client-Side Validation
- **File Size Limits**: Configurable maximum file size (default: 10MB)
- **File Type Validation**: Validates MIME types and file extensions
- **Extension Consistency**: Ensures file extensions match their MIME types
- **Dangerous File Detection**: Blocks potentially harmful file types
- **Double Extension Prevention**: Detects and blocks files with double extensions
- **Path Traversal Prevention**: Blocks files with '..' in names

### Built-in Security Checks
1. **Executable File Blocking**: Automatically blocks .exe, .bat, .cmd, .sh, .ps1, .vbs, .js, .jar, .com, .scr, .msi, .dll files
2. **MIME Type Verification**: Ensures file extensions match expected MIME types
3. **Input Sanitization**: Uses the InputValidator from the security module

## Server-Side Requirements

⚠️ **Important**: Client-side validation is not sufficient for security. The server MUST implement the following:

### 1. File Type Validation
```python
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'}
ALLOWED_MIME_TYPES = {
    'image/jpeg': ['jpg', 'jpeg'],
    'image/png': ['png'],
    'image/gif': ['gif'],
    'application/pdf': ['pdf'],
    'application/msword': ['doc'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx']
}

def validate_file_type(file):
    # Check file extension
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("File type not allowed")
    
    # Verify MIME type matches extension
    mime_type = file.content_type
    if mime_type not in ALLOWED_MIME_TYPES:
        raise ValueError("Invalid MIME type")
    
    if ext not in ALLOWED_MIME_TYPES[mime_type]:
        raise ValueError("File extension does not match MIME type")
```

### 2. File Size Limits
```python
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

def validate_file_size(file):
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset to beginning
    
    if size > MAX_FILE_SIZE:
        raise ValueError(f"File too large. Maximum size is {MAX_FILE_SIZE} bytes")
```

### 3. Content Scanning
```python
import magic  # python-magic library

def scan_file_content(file):
    # Check actual file type using magic bytes
    file_type = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    
    if file_type not in ALLOWED_MIME_TYPES:
        raise ValueError("File content does not match allowed types")
    
    # Additional malware scanning should be implemented here
    # Consider using ClamAV or similar
```

### 4. Filename Sanitization
```python
import os
import re

def sanitize_filename(filename):
    # Remove path components
    filename = os.path.basename(filename)
    
    # Remove dangerous characters
    filename = re.sub(r'[^\w\s.-]', '', filename)
    
    # Limit length
    name, ext = os.path.splitext(filename)
    if len(name) > 100:
        name = name[:100]
    
    return f"{name}{ext}"
```

### 5. Storage Security
```python
import uuid

def store_file_securely(file, user_id):
    # Generate unique filename to prevent conflicts and path traversal
    unique_id = str(uuid.uuid4())
    _, ext = os.path.splitext(file.filename)
    new_filename = f"{unique_id}{ext}"
    
    # Store outside web root
    upload_path = os.path.join(SECURE_UPLOAD_DIR, user_id, new_filename)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(upload_path), exist_ok=True)
    
    # Save file with restricted permissions
    file.save(upload_path)
    os.chmod(upload_path, 0o640)
    
    return new_filename
```

### 6. Access Control
```python
def serve_file(file_id, user_id):
    # Verify user has permission to access file
    file_record = db.query(File).filter_by(id=file_id, owner_id=user_id).first()
    if not file_record:
        raise PermissionError("Access denied")
    
    # Serve file with proper headers
    response = send_file(file_record.path)
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Disposition'] = f'attachment; filename="{file_record.original_name}"'
    
    return response
```

## Usage Example

```tsx
import { SecureFileUpload } from '@/components/SecureFileUpload';

function ProfilePictureUpload() {
  const handleUpload = async (files: File[]) => {
    const formData = new FormData();
    formData.append('file', files[0]);
    
    const response = await fetch('/api/upload/profile-picture', {
      method: 'POST',
      body: formData,
      headers: {
        'X-CSRF-Token': getCsrfToken(),
      },
    });
    
    if (!response.ok) {
      throw new Error('Upload failed');
    }
  };

  return (
    <SecureFileUpload
      accept="image/jpeg,image/png,image/webp"
      maxSize={5 * 1024 * 1024} // 5MB
      maxFiles={1}
      allowedTypes={['image/jpeg', 'image/png', 'image/webp']}
      allowedExtensions={['jpg', 'jpeg', 'png', 'webp']}
      onUpload={handleUpload}
      onError={(error) => console.error(error)}
      label="Profile Picture"
      helpText="Upload a profile picture (JPG, PNG, or WebP, max 5MB)"
    />
  );
}
```

## Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| accept | string | - | HTML accept attribute for file input |
| maxSize | number | 10MB | Maximum file size in bytes |
| maxFiles | number | 5 | Maximum number of files |
| allowedTypes | string[] | [] | Allowed MIME types |
| allowedExtensions | string[] | [] | Allowed file extensions |
| onUpload | (files: File[]) => Promise<void> | required | Upload handler |
| onError | (error: string) => void | - | Error handler |
| className | string | '' | Additional CSS classes |
| disabled | boolean | false | Disable the component |
| label | string | - | Field label |
| helpText | string | - | Help text displayed below |
| required | boolean | false | Mark field as required |

## Security Considerations

1. **Never Trust Client-Side Validation**: Always implement server-side validation
2. **Store Files Outside Web Root**: Prevent direct access to uploaded files
3. **Use Random Filenames**: Prevent directory traversal and name conflicts
4. **Implement Virus Scanning**: Use ClamAV or similar for malware detection
5. **Set Proper Permissions**: Restrict file permissions (e.g., 640)
6. **Implement Rate Limiting**: Prevent abuse and DoS attacks
7. **Log Upload Activities**: Monitor for suspicious patterns
8. **Use CDN with Security Headers**: When serving files, use proper security headers

## Testing Checklist

- [ ] Test with various file types (valid and invalid)
- [ ] Test file size limits
- [ ] Test multiple file uploads
- [ ] Test drag and drop functionality
- [ ] Test keyboard accessibility
- [ ] Test error handling and recovery
- [ ] Test with malformed files
- [ ] Test with files containing special characters
- [ ] Test concurrent uploads
- [ ] Test network interruptions during upload