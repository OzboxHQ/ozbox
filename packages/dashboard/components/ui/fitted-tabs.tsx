"use client"

/**
 * A row of sub-tabs that FITS its container — a short sub-tab row, so every one looks and
 * behaves the same.
 *
 * Why a sibling of `tabs.tsx` rather than props on `TabsList`: the plain
 * list is right for a page-level strip; this one is the compact, touch-safe sub-row.
 *
 *   • `fill` (default) — BELOW lg the list takes the full width and the triggers split it equally (touch-sized
 *     targets on a phone or tablet). FROM lg UP it HUGS its labels: the list is as wide as its triggers and no
 *     trigger stretches past its text. A row that cannot fit
 *     scrolls sideways INSIDE the list, never the page.
 *   • `fill={false}` — the list hugs its triggers at every width (still capped at its container).
 *   • Height is 52px (a 44px trigger inside the list's padding) below `lg` and a compact 36px from `lg`
 *     up (triggers 28px tall with `py-1`, inside the list's 4px padding, so a trigger never overflows the list and clips its border), where the pointer is a mouse — the same split `TAP_ACTION` uses.
 *   • Labels never wrap; icons are optional and sized `h-3.5 w-3.5` by the caller for consistency.
 *
 * Needs a `Tabs` root above it, like any tab list.
 */
import * as React from "react"

import { TabsList, TabsTrigger } from "@/components/ui/tabs"
import { cn } from "@/lib/utils"

export interface FittedTabsListProps extends React.ComponentPropsWithoutRef<typeof TabsList> {
  /** Take the full width and split it equally between the triggers. Default true. */
  fill?: boolean
}

export const FittedTabsList = React.forwardRef<React.ElementRef<typeof TabsList>, FittedTabsListProps>(
  ({ className, fill = true, ...props }, ref) => (
    <TabsList
      ref={ref}
      className={cn(
        "h-[52px] max-w-full justify-start gap-1 overflow-x-auto no-scrollbar lg:h-9",
        fill ? "w-full lg:w-auto lg:[&>*]:flex-none" : "[&>*]:flex-none",
        className,
      )}
      {...props}
    />
  ),
)
FittedTabsList.displayName = "FittedTabsList"

export const FittedTabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsTrigger>,
  React.ComponentPropsWithoutRef<typeof TabsTrigger>
>(({ className, ...props }, ref) => (
  <TabsTrigger ref={ref} className={cn("h-full flex-1 gap-1.5 py-0 text-xs lg:h-7 lg:px-4 lg:py-1", className)} {...props} />
))
FittedTabsTrigger.displayName = "FittedTabsTrigger"
