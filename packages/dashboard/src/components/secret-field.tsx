import { forwardRef, type InputHTMLAttributes } from 'react';

import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

/**
 * A write-only field: a labelled password input that is never pre-filled and is cleared by its form after a save.
 * Nothing in the dashboard reads a saved secret back, so there is nothing to show.
 */
export const SecretField = forwardRef<HTMLInputElement, { id: string; label: string; hint?: string; revealed?: boolean } & Omit<InputHTMLAttributes<HTMLInputElement>, 'id' | 'type'>>(
  ({ id, label, hint, revealed, ...rest }, ref) => (
    <div className="space-y-1">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        ref={ref}
        type={revealed ? 'text' : 'password'}
        autoComplete="off"
        autoCapitalize="off"
        spellCheck={false}
        data-1p-ignore="true"
        className="max-lg:h-11"
        aria-describedby={hint ? `${id}-hint` : undefined}
        {...rest}
      />
      {hint ? (
        <p id={`${id}-hint`} className="text-xs text-muted-foreground">
          {hint}
        </p>
      ) : null}
    </div>
  ),
);
SecretField.displayName = 'SecretField';
