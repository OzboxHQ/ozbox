"use client";

import * as React from "react";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import { Check } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * A checkbox whose hit area is 44 x 44 px below lg (the visible box stays 20 px) and 20 px from lg up. A sibling of
 * `checkbox.tsx`, which keeps its compact size for dense tables.
 */
const TouchCheckbox = React.forwardRef<
  React.ElementRef<typeof CheckboxPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof CheckboxPrimitive.Root>
>(({ className, ...props }, ref) => (
  <CheckboxPrimitive.Root
    ref={ref}
    className={cn(
      "group peer inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-sm focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50 lg:h-5 lg:w-5",
      className,
    )}
    {...props}
  >
    <span className="flex h-5 w-5 items-center justify-center rounded-sm border border-primary ring-offset-background group-focus-visible:ring-2 group-focus-visible:ring-ring group-focus-visible:ring-offset-2 group-data-[state=checked]:bg-primary group-data-[state=checked]:text-primary-foreground">
      <CheckboxPrimitive.Indicator className="flex items-center justify-center text-current">
        <Check className="h-4 w-4" />
      </CheckboxPrimitive.Indicator>
    </span>
  </CheckboxPrimitive.Root>
));
TouchCheckbox.displayName = "TouchCheckbox";

export { TouchCheckbox };
