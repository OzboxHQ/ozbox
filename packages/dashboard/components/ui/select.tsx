"use client"

/**
 * Select — and the two height bugs it shipped with.
 *
 * ── ⚠️ 1. THE DROPDOWN WAS ONE ROW TALL, EVERYWHERE ───────────────────────
 *
 * The stock viewport class list carried
 * `h-[var(--radix-select-trigger-height)]` in popper mode. Radix sets that
 * custom property on the CONTENT element's inline style, so it INHERITS down to
 * the viewport — and the viewport's height became the height of the trigger
 * that opened it. Every `SelectTrigger` in this product is `h-10`, so every
 * popper-positioned dropdown rendered a 40px scroll window: one visible option,
 * the rest reachable only by dragging inside a box the size of a single row.
 *
 * It reads as "the list is cut off at the bottom", it was reported that way
 * against the claim form's **Place of Service**, **Claim Filing Code** and
 * **Payment Responsibility**, and it was never those three controls — they are
 * plain `<SelectContent>` with no overrides. It was this file, under every
 * dropdown in the product.
 *
 * The height is now the content's own, bounded by rule 2.
 *
 * ── ⚠️ 2. `max-h-96` GUESSED AT THE ROOM IT HAD ───────────────────────────
 *
 * A fixed 24rem ceiling knows nothing about where the trigger sits. Radix
 * flips the panel to the other side when it collides, but when NEITHER side has
 * 24rem — a select low in a sheet, a laptop viewport, a phone in landscape —
 * the panel is taller than the space and the last options sit under the fold
 * with no way to reach them.
 *
 * `--radix-select-content-available-height` is the room Radix has actually
 * measured between the trigger and the viewport edge, so the ceiling is now
 * `min(24rem, whatever there really is)` and the overflow scrolls INSIDE the
 * panel.
 *
 * ⚠️ Keep the `min()`. Using the variable alone lets a select at the top of a
 * tall monitor open a 900px list.
 */

import * as React from "react"
import * as SelectPrimitive from "@radix-ui/react-select"
import { Check, ChevronDown, ChevronUp } from "lucide-react"

import { cn } from "@/lib/utils"
import { TAP_FIELD_FLOOR } from "@/components/ui/tap-target"
import { POPOVER_LIST_SCROLL_GUARDS } from "@/components/ui/popover-list-scroll"

const Select = SelectPrimitive.Root

const SelectGroup = SelectPrimitive.Group

const SelectValue = SelectPrimitive.Value

const SelectTrigger = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Trigger>
>(({ className, children, ...props }, ref) => (
  <SelectPrimitive.Trigger
    ref={ref}
    className={cn(
      // TAP_FIELD_FLOOR: 44px minimum below lg for every caller (h-10, or a compact h-8 / h-9); desktop unchanged
      TAP_FIELD_FLOOR,
      "flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 [&>span]:line-clamp-1",
      className
    )}
    {...props}
  >
    {children}
    <SelectPrimitive.Icon asChild>
      <ChevronDown className="h-4 w-4 opacity-50" />
    </SelectPrimitive.Icon>
  </SelectPrimitive.Trigger>
))
SelectTrigger.displayName = SelectPrimitive.Trigger.displayName

const SelectScrollUpButton = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.ScrollUpButton>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.ScrollUpButton>
>(({ className, ...props }, ref) => (
  <SelectPrimitive.ScrollUpButton
    ref={ref}
    className={cn(
      "flex cursor-default items-center justify-center py-1",
      className
    )}
    {...props}
  >
    <ChevronUp className="h-4 w-4" />
  </SelectPrimitive.ScrollUpButton>
))
SelectScrollUpButton.displayName = SelectPrimitive.ScrollUpButton.displayName

const SelectScrollDownButton = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.ScrollDownButton>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.ScrollDownButton>
>(({ className, ...props }, ref) => (
  <SelectPrimitive.ScrollDownButton
    ref={ref}
    className={cn(
      "flex cursor-default items-center justify-center py-1",
      className
    )}
    {...props}
  >
    <ChevronDown className="h-4 w-4" />
  </SelectPrimitive.ScrollDownButton>
))
SelectScrollDownButton.displayName =
  SelectPrimitive.ScrollDownButton.displayName

/**
 * A dialog's scroll lock cancels every wheel event that starts outside the dialog, and this list is
 * portaled to <body>. So the list scrolls ITSELF: a non-passive listener on the viewport moves
 * `scrollTop` by the wheel's delta and keeps the event from reaching the lock  (with a mouse, inside a sheet).
 */
const wheelCleanup = new WeakMap<HTMLElement, () => void>()
function scrollOnWheel(node: HTMLDivElement | null) {
  if (!node) return
  if (wheelCleanup.has(node)) return
  const onWheel = (event: WheelEvent) => {
    if (node.scrollHeight <= node.clientHeight) return
    event.preventDefault()
    event.stopPropagation()
    // deltaMode 1 = lines (Firefox, some mice); 0 = pixels.
    node.scrollTop += event.deltaMode === 1 ? event.deltaY * 16 : event.deltaY
  }
  node.addEventListener("wheel", onWheel, { passive: false })
  wheelCleanup.set(node, () => node.removeEventListener("wheel", onWheel))
}

const SelectContent = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Content>
>(({ className, children, position = "popper", ...props }, ref) => (
  <SelectPrimitive.Portal>
    <SelectPrimitive.Content
      ref={ref}
      className={cn(
        "relative z-50 max-h-[min(24rem,var(--radix-select-content-available-height))] min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2",
        position === "popper" &&
          "data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1",
        className
      )}
      position={position}
      // The list is portaled outside the Dialog / PanelSheet that opened it, and the dialog's scroll
      // lock cancels every wheel whose target is outside the dialog — so a mouse could never scroll
      // a long list. Same guard the popover lists use.
      {...POPOVER_LIST_SCROLL_GUARDS}
      {...props}
    >
      <SelectScrollUpButton />
      <SelectPrimitive.Viewport
        ref={scrollOnWheel}
        className={cn(
          "p-1",
          // ⚠️ NO `h-[var(--radix-select-trigger-height)]` HERE. See the note
          // at the top of this file — that one class made every dropdown in
          // the product exactly one row tall.
          position === "popper" && "w-full min-w-[var(--radix-select-trigger-width)]"
        )}
      >
        {children}
      </SelectPrimitive.Viewport>
      <SelectScrollDownButton />
    </SelectPrimitive.Content>
  </SelectPrimitive.Portal>
))
SelectContent.displayName = SelectPrimitive.Content.displayName

const SelectLabel = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Label>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Label>
>(({ className, ...props }, ref) => (
  <SelectPrimitive.Label
    ref={ref}
    className={cn("py-1.5 pl-8 pr-2 text-sm font-semibold", className)}
    {...props}
  />
))
SelectLabel.displayName = SelectPrimitive.Label.displayName

const SelectItem = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Item>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Item>
>(({ className, children, ...props }, ref) => (
  <SelectPrimitive.Item
    ref={ref}
    className={cn(
      "relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
      className
    )}
    {...props}
  >
    <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
      <SelectPrimitive.ItemIndicator>
        <Check className="h-4 w-4" />
      </SelectPrimitive.ItemIndicator>
    </span>

    <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
  </SelectPrimitive.Item>
))
SelectItem.displayName = SelectPrimitive.Item.displayName

const SelectSeparator = React.forwardRef<
  React.ElementRef<typeof SelectPrimitive.Separator>,
  React.ComponentPropsWithoutRef<typeof SelectPrimitive.Separator>
>(({ className, ...props }, ref) => (
  <SelectPrimitive.Separator
    ref={ref}
    className={cn("-mx-1 my-1 h-px bg-muted", className)}
    {...props}
  />
))
SelectSeparator.displayName = SelectPrimitive.Separator.displayName

export {
  Select,
  SelectGroup,
  SelectValue,
  SelectTrigger,
  SelectContent,
  SelectLabel,
  SelectItem,
  SelectSeparator,
  SelectScrollUpButton,
  SelectScrollDownButton,
}
