/**
 * Make an option list inside a popover scrollable wherever it opens.
 *
 * A reported problem: "the open list cannot be scrolled to the end; the last options are
 * hidden". Two causes, both here:
 *
 * 1. INSIDE A SHEET OR DIALOG THE WHEEL DID NOTHING. A combobox's list is a
 *    popover portaled to <body>, i.e. OUTSIDE the dialog that opened it, and a
 *    Radix Dialog locks page scrolling: it cancels every wheel and touch-move
 *    whose target is outside the dialog. The list could still be dragged on a
 *    touch screen's own scroller and moved with arrow keys, but a mouse wheel
 *    did nothing - which is exactly "only touchscreen PCs can scroll". The
 *    guards below stop the event reaching the lock, so the list scrolls itself.
 *
 * 2. SOME LISTS GUESSED THEIR HEIGHT. A list with its own fixed `max-h` knows
 *    nothing about where its trigger sits, so low in a sheet or on a short
 *    screen it ran past the bottom of the window with its last options under the
 *    fold. `POPOVER_LIST_BOUNDS` is the room Radix actually measured, capped by
 *    a sane maximum (the `min()` matters: the variable alone opens a 900px list
 *    on a tall monitor).
 *
 * Usage (a sibling, not new props on the primitives):
 *
 *   <PopoverContent
 *     className={cn(POPOVER_LIST_BOUNDS, "w-[var(--radix-popover-trigger-width)]")}
 *     {...POPOVER_LIST_SCROLL_GUARDS}
 *   >
 *     <Command className={POPOVER_LIST_COMMAND}>
 *       <CommandInput />
 *       <CommandList className={POPOVER_LIST_SCROLLER}>
 */

import type * as React from "react"

/** The panel: a flex column no taller than the room that exists. */
export const POPOVER_LIST_BOUNDS =
  "flex flex-col max-h-[min(21.875rem,var(--radix-popover-content-available-height))] p-0"

/** The Command root inside it: `flex-1 min-h-0` does the sizing, `h-auto` beats the primitive's `h-full`. */
export const POPOVER_LIST_COMMAND = "h-auto min-h-0 flex-1"

/** The list itself: scrolls inside the panel, and never chains the scroll to the page behind. */
export const POPOVER_LIST_SCROLLER = "min-h-0 flex-1 max-h-none overflow-y-auto overscroll-contain"

function keepScrollInsideList(event: React.SyntheticEvent) {
  event.stopPropagation()
}

/** Spread onto the PopoverContent. */
export const POPOVER_LIST_SCROLL_GUARDS = {
  onWheel: keepScrollInsideList,
  onTouchMove: keepScrollInsideList,
} as const
