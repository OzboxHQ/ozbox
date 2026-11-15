import * as React from 'react';

import { cn } from '@/lib/utils';
import { Input } from '@/components/ui/input';
import { TAP_FIELD_FLOOR } from '@/components/ui/tap-target';

export interface ComboboxOption {
  value: string;
  label: string;
}

/** Words typed must all appear in the label, in any order, ignoring case. */
export function filterOptions(options: readonly ComboboxOption[], query: string, limit = 100): ComboboxOption[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const hits = words.length === 0 ? options : options.filter((o) => words.every((w) => o.label.toLowerCase().includes(w)));
  return hits.slice(0, limit);
}

interface ComboboxProps {
  options: readonly ComboboxOption[];
  value: string;
  onValueChange: (value: string) => void;
  /** The accessible name (also use a visible <Label htmlFor={id}>). */
  label: string;
  placeholder?: string;
  emptyText: string;
  id?: string;
  className?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: boolean | 'true' | 'false';
}

/**
 * A searchable list for choices too long for a plain select (time zones, countries). The list opens in the flow of the
 * page, not as a floating layer, so it is never clipped by a sheet and scrolls inside its own box. It is a sibling of
 * the other primitives, not an option on them.
 */
export function Combobox({ options, value, onValueChange, label, placeholder, emptyText, id, className, ...aria }: ComboboxProps) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState('');
  const [active, setActive] = React.useState(0);
  const root = React.useRef<HTMLDivElement>(null);
  const uid = React.useId();
  const listId = `${uid}-list`;
  const shown = React.useMemo(() => filterOptions(options, query), [options, query]);
  const selected = options.find((o) => o.value === value);
  const idx = Math.min(active, Math.max(0, shown.length - 1));

  const choose = (o: ComboboxOption) => {
    onValueChange(o.value);
    setOpen(false);
    setQuery('');
  };

  return (
    <div
      ref={root}
      className={cn('space-y-1', className)}
      onBlur={(e) => {
        if (!root.current?.contains(e.relatedTarget as Node | null)) {
          setOpen(false);
          setQuery('');
        }
      }}
    >
      <Input
        id={id}
        role="combobox"
        aria-expanded={open}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-label={label}
        aria-activedescendant={open && shown[idx] ? `${uid}-o-${idx}` : undefined}
        autoComplete="off"
        placeholder={placeholder}
        className={cn('h-11', TAP_FIELD_FLOOR)}
        value={open ? query : (selected?.label ?? value)}
        onFocus={() => setOpen(true)}
        onClick={() => setOpen(true)}
        onChange={(e) => {
          setQuery(e.target.value);
          setActive(0);
          setOpen(true);
        }}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            setOpen(true);
            setActive(Math.min(idx + 1, shown.length - 1));
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setActive(Math.max(idx - 1, 0));
          } else if (e.key === 'Enter' && open && shown[idx]) {
            e.preventDefault();
            choose(shown[idx]);
          } else if (e.key === 'Escape' && open) {
            e.stopPropagation();
            setOpen(false);
            setQuery('');
          }
        }}
        {...aria}
      />
      {open && (
        <ul id={listId} role="listbox" aria-label={label} className="max-h-56 overflow-y-auto rounded-md border bg-background p-1">
          {shown.length === 0 ? (
            <li role="presentation" className="px-3 py-2 text-sm text-muted-foreground">
              {emptyText}
            </li>
          ) : (
            shown.map((o, i) => (
              <li
                key={o.value}
                id={`${uid}-o-${i}`}
                role="option"
                aria-selected={o.value === value}
                className={cn('flex min-h-11 cursor-pointer items-center rounded-sm px-3 text-sm lg:min-h-9', i === idx ? 'bg-accent' : 'hover:bg-accent/60', o.value === value && 'font-semibold')}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => choose(o)}
              >
                {o.label}
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  );
}
