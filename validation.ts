import { z } from 'zod';
import {
  emailSchema,
  passwordSchema,
  phoneSchema,
  uuidSchema,
  nonEmptyString,
  emptyStringAsNull,
  arrayWithConstraints,
} from './common';

// ============================================
// Field Validation Schemas
// ============================================

/**
 * Username validation with availability check
 */
export const usernameValidationSchema = z.object({
  username: z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username must not exceed 30 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens')
    .refine(
      async (username) => {
        // Mock availability check - replace with actual API call
        return !['admin', 'root', 'test'].includes(username.toLowerCase());
      },
      'Username is not available'
    ),
});

/**
 * Email validation with domain verification
 */
export const emailValidationSchema = z.object({
  email: emailSchema
    .refine(
      async (email) => {
        // Mock domain check - replace with actual validation
        const domain = email.split('@')[1];
        const blockedDomains = ['tempmail.com', '10minutemail.com'];
        return !blockedDomains.includes(domain);
      },
      'Email domain is not allowed'
    ),
});

/**
 * Phone number validation with format verification
 */
export const phoneValidationSchema = z.object({
  phoneNumber: phoneSchema,
  countryCode: z.string().length(2, 'Country code must be 2 characters'),
});

/**
 * Password strength validation
 */
export const passwordStrengthSchema = z.object({
  password: passwordSchema
    .refine(
      (password) => {
        // Check for common passwords
        const commonPasswords = ['password', '12345678', 'qwerty123'];
        return !commonPasswords.includes(password.toLowerCase());
      },
      'Password is too common'
    )
    .refine(
      (password) => {
        // Check for keyboard patterns
        const patterns = ['qwerty', 'asdfgh', '123456', 'abcdef'];
        return !patterns.some(pattern => password.toLowerCase().includes(pattern));
      },
      'Password contains keyboard patterns'
    ),
  confirmPassword: z.string(),
}).refine(
  (data) => data.password === data.confirmPassword,
  {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  }
);

// ============================================
// Form Validation Schemas
// ============================================

/**
 * Contact form validation
 */
export const contactFormSchema = z.object({
  firstName: nonEmptyString.max(50, 'First name must not exceed 50 characters'),
  lastName: nonEmptyString.max(50, 'Last name must not exceed 50 characters'),
  email: emailSchema,
  phone: phoneSchema.optional(),
  company: z.string().max(100, 'Company name must not exceed 100 characters').optional(),
  subject: nonEmptyString.max(200, 'Subject must not exceed 200 characters'),
  message: nonEmptyString
    .min(10, 'Message must be at least 10 characters')
    .max(2000, 'Message must not exceed 2000 characters'),
  consent: z.boolean().refine(val => val === true, 'You must agree to the privacy policy'),
  newsletter: z.boolean().default(false),
});

/**
 * File upload validation
 */
export const fileUploadSchema = z.object({
  file: z.instanceof(File)
    .refine(file => file.size <= 10 * 1024 * 1024, 'File size must be less than 10MB')
    .refine(
      file => ['image/jpeg', 'image/png', 'image/gif', 'image/webp'].includes(file.type),
      'File must be an image (JPEG, PNG, GIF, or WebP)'
    ),
  altText: z.string().max(255, 'Alt text must not exceed 255 characters').optional(),
  caption: z.string().max(500, 'Caption must not exceed 500 characters').optional(),
});

/**
 * Document upload validation
 */
export const documentUploadSchema = z.object({
  file: z.instanceof(File)
    .refine(file => file.size <= 50 * 1024 * 1024, 'File size must be less than 50MB')
    .refine(
      file => [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain',
        'image/jpeg',
        'image/png'
      ].includes(file.type),
      'File must be PDF, Word document, text file, or image'
    ),
  category: z.enum(['identity', 'license', 'certificate', 'contract', 'other']),
  description: z.string().max(500, 'Description must not exceed 500 characters').optional(),
  expiryDate: z.string().datetime().optional(),
});

/**
 * Address validation
 */
export const addressValidationSchema = z.object({
  street: nonEmptyString.max(255, 'Street address must not exceed 255 characters'),
  city: nonEmptyString.max(100, 'City must not exceed 100 characters'),
  state: z.string().max(100, 'State must not exceed 100 characters').optional(),
  postalCode: z.string()
    .min(3, 'Postal code must be at least 3 characters')
    .max(20, 'Postal code must not exceed 20 characters'),
  country: z.string().length(2, 'Country must be a 2-character ISO code'),
  type: z.enum(['billing', 'shipping', 'both']).default('both'),
  isDefault: z.boolean().default(false),
});

/**
 * Credit card validation
 */
export const creditCardSchema = z.object({
  cardNumber: z.string()
    .regex(/^[0-9]{13,19}$/, 'Card number must be 13-19 digits')
    .refine(
      (cardNumber) => {
        // Luhn algorithm validation
        let sum = 0;
        let alternate = false;
        for (let i = cardNumber.length - 1; i >= 0; i--) {
          let digit = parseInt(cardNumber.charAt(i), 10);
          if (alternate) {
            digit *= 2;
            if (digit > 9) {
              digit = (digit % 10) + 1;
            }
          }
          sum += digit;
          alternate = !alternate;
        }
        return sum % 10 === 0;
      },
      'Invalid card number'
    ),
  expiryMonth: z.number().min(1).max(12),
  expiryYear: z.number().min(new Date().getFullYear()),
  cvv: z.string().regex(/^[0-9]{3,4}$/, 'CVV must be 3 or 4 digits'),
  cardholderName: nonEmptyString.max(100, 'Cardholder name must not exceed 100 characters'),
});

/**
 * Search/filter validation
 */
export const searchFilterSchema = z.object({
  query: z.string().max(255, 'Search query must not exceed 255 characters').optional(),
  category: z.string().optional(),
  tags: arrayWithConstraints(z.string(), { max: 10, maxMessage: 'Too many tags selected' }).optional(),
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional(),
  priceMin: z.number().min(0, 'Minimum price cannot be negative').optional(),
  priceMax: z.number().min(0, 'Maximum price cannot be negative').optional(),
  sortBy: z.enum(['relevance', 'date', 'price', 'rating']).default('relevance'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
  page: z.number().min(1, 'Page must be at least 1').default(1),
  limit: z.number().min(1).max(100, 'Limit must be between 1 and 100').default(20),
}).refine(
  (data) => {
    if (data.priceMin !== undefined && data.priceMax !== undefined) {
      return data.priceMin <= data.priceMax;
    }
    return true;
  },
  {
    message: 'Minimum price cannot be greater than maximum price',
    path: ['priceMin'],
  }
).refine(
  (data) => {
    if (data.dateFrom && data.dateTo) {
      return new Date(data.dateFrom) <= new Date(data.dateTo);
    }
    return true;
  },
  {
    message: 'Start date cannot be after end date',
    path: ['dateFrom'],
  }
);

// ============================================
// Bulk Operation Validation
// ============================================

/**
 * Bulk update validation
 */
export const bulkUpdateSchema = z.object({
  ids: arrayWithConstraints(
    uuidSchema,
    { 
      min: 1, 
      max: 100,
      minMessage: 'At least one item must be selected',
      maxMessage: 'Cannot update more than 100 items at once'
    }
  ),
  operation: z.enum(['update', 'delete', 'archive', 'activate']),
  data: z.record(z.unknown()).optional(),
  reason: z.string().max(500, 'Reason must not exceed 500 characters').optional(),
});

/**
 * Bulk import validation
 */
export const bulkImportSchema = z.object({
  file: z.instanceof(File)
    .refine(file => file.size <= 10 * 1024 * 1024, 'File size must be less than 10MB')
    .refine(
      file => ['text/csv', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'].includes(file.type),
      'File must be CSV or Excel format'
    ),
  mapping: z.record(
    z.string(), // CSV column name
    z.string()  // Database field name
  ),
  options: z.object({
    skipHeader: z.boolean().default(true),
    delimiter: z.string().length(1).default(','),
    encoding: z.enum(['utf-8', 'latin1', 'ascii']).default('utf-8'),
    dryRun: z.boolean().default(false),
    updateExisting: z.boolean().default(false),
  }).default({}),
});

// ============================================
// Dynamic Validation Builders
// ============================================

/**
 * Create validation schema for dynamic forms
 */
export const createDynamicFormSchema = (fields: Array<{
  name: string;
  type: 'string' | 'number' | 'boolean' | 'email' | 'phone' | 'url';
  required?: boolean;
  min?: number;
  max?: number;
  pattern?: string;
  options?: string[];
}>) => {
  const schemaObject: Record<string, z.ZodTypeAny> = {};

  fields.forEach(field => {
    let schema: z.ZodTypeAny;

    switch (field.type) {
      case 'email':
        schema = emailSchema;
        break;
      case 'phone':
        schema = phoneSchema;
        break;
      case 'url':
        schema = z.string().url();
        break;
      case 'number':
        schema = z.number();
        if (field.min !== undefined) schema = schema.min(field.min);
        if (field.max !== undefined) schema = schema.max(field.max);
        break;
      case 'boolean':
        schema = z.boolean();
        break;
      default:
        schema = z.string();
        if (field.min !== undefined) schema = schema.min(field.min);
        if (field.max !== undefined) schema = schema.max(field.max);
        if (field.pattern) schema = schema.regex(new RegExp(field.pattern));
        if (field.options) schema = z.enum(field.options as [string, ...string[]]);
    }

    if (!field.required) {
      schema = schema.optional();
    }

    schemaObject[field.name] = schema;
  });

  return z.object(schemaObject);
};

/**
 * Create conditional validation schema
 */
export const createConditionalSchema = <T extends Record<string, z.ZodTypeAny>>(
  baseSchema: z.ZodObject<T>,
  conditions: Array<{
    when: (data: z.infer<z.ZodObject<T>>) => boolean;
    then: z.ZodObject<any>;
    otherwise?: z.ZodObject<any>;
  }>
) => {
  return baseSchema.superRefine((data, ctx) => {
    conditions.forEach(condition => {
      const schema = condition.when(data) ? condition.then : condition.otherwise;
      if (schema) {
        const result = schema.safeParse(data);
        if (!result.success) {
          result.error.issues.forEach(issue => {
            ctx.addIssue(issue);
          });
        }
      }
    });
  });
};

// ============================================
// Validation Utilities
// ============================================

/**
 * Validate field with debouncing for async validation
 */
export const createDebouncedValidator = (schema: z.ZodSchema, delay: number = 300) => {
  let timeoutId: NodeJS.Timeout;
  
  return (value: unknown): Promise<{ success: boolean; errors?: string[] }> => {
    return new Promise((resolve) => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(async () => {
        try {
          await schema.parseAsync(value);
          resolve({ success: true });
        } catch (error) {
          if (error instanceof z.ZodError) {
            resolve({
              success: false,
              errors: error.issues.map(issue => issue.message)
            });
          } else {
            resolve({
              success: false,
              errors: ['Validation failed']
            });
          }
        }
      }, delay);
    });
  };
};

/**
 * Transform validation errors to field-specific format
 */
export const transformValidationErrors = (error: z.ZodError): Record<string, string[]> => {
  const fieldErrors: Record<string, string[]> = {};
  
  error.issues.forEach(issue => {
    const path = issue.path.join('.');
    if (!fieldErrors[path]) {
      fieldErrors[path] = [];
    }
    fieldErrors[path].push(issue.message);
  });
  
  return fieldErrors;
};

/**
 * Get validation summary
 */
export const getValidationSummary = (errors: Record<string, string[]>) => {
  const fields = Object.keys(errors);
  const totalErrors = Object.values(errors).reduce((sum, errs) => sum + errs.length, 0);
  
  return {
    hasErrors: totalErrors > 0,
    errorCount: totalErrors,
    fieldCount: fields.length,
    fields,
    summary: totalErrors > 0 
      ? `${totalErrors} error${totalErrors === 1 ? '' : 's'} in ${fields.length} field${fields.length === 1 ? '' : 's'}`
      : 'All fields are valid'
  };
};

// Type exports
export type ContactForm = z.infer<typeof contactFormSchema>;
export type FileUpload = z.infer<typeof fileUploadSchema>;
export type DocumentUpload = z.infer<typeof documentUploadSchema>;
export type AddressValidation = z.infer<typeof addressValidationSchema>;
export type CreditCard = z.infer<typeof creditCardSchema>;
export type SearchFilter = z.infer<typeof searchFilterSchema>;
export type BulkUpdate = z.infer<typeof bulkUpdateSchema>;
export type BulkImport = z.infer<typeof bulkImportSchema>;
export type ValidationErrors = Record<string, string[]>;
export type ValidationSummary = ReturnType<typeof getValidationSummary>;