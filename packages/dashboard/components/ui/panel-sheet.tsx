"use client"

/**
 * PanelSheet — the wide, floating overlay for CONTENT-HEAVY forms.
 *
 * ⚠️ A SIBLING OF `sheet.tsx`, NOT A NEW `side` ON IT. The standing rule for
 * `components/ui/` is that a primitive with many consumers gets a new FILE
 * rather than new optional props or variants: every existing `<SheetContent>`
 * caller in the product would otherwise have to be re-read against a wider
 * surface, and the edge-anchored drawer and this floating panel are genuinely
 * different objects, not two settings of one.
 *
 * ── What it is ────────────────────────────────────────────────────────────
 *
 * DESKTOP (md+): a floating rectangle inset from every edge — ~75vw, anchored
 * right, rounded on ALL FOUR sides, with a real margin all round so the page
 * behind it stays visible as context. `sheet.tsx`'s `right` variant caps at
 * `xl:max-w-xl` (576px), which is why a long form read as a column of squeezed fields on
 * a 1440px monitor with two thirds of the screen empty.
 *
 * MOBILE (<md): a bottom sheet at 92vh with a rounded top edge and a grab
 * handle — the reachable shape on a phone. A right-edge drawer that is 100%
 * wide is just a page that animates in from the side; this one is honest
 * about being a sheet.
 *
 * ── Why the header/body/footer split is not decoration ─────────────────────
 *
 * A sheet that puts `overflow-y-auto` on the CONTENT ITSELF lets
 * the title scroll away with the fields and makes the submit button reachable
 * only after scrolling to the bottom of a long form. Here the panel is a flex
 * column: `PanelSheetHeader` and `PanelSheetFooter` are fixed, and ONLY
 * `PanelSheetBody` scrolls. On a phone that is the difference between a save
 * button you can find and one you cannot.
 *
 * ⚠️ `PanelSheetFooter` carries the iOS safe-area inset. Without it the submit
 * button sits under the home indicator on a notched phone.
 */

import * as React from "react"
import * as SheetPrimitive from "@radix-ui/react-dialog"
import { cva, type VariantProps } from "class-variance-authority"
import { Cancel01Icon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { cn } from "@/lib/utils"

const PanelSheet = SheetPrimitive.Root
const PanelSheetTrigger = SheetPrimitive.Trigger
const PanelSheetClose = SheetPrimitive.Close
const PanelSheetPortal = SheetPrimitive.Portal

const PanelSheetOverlay = React.forwardRef<
  React.ElementRef<typeof SheetPrimitive.Overlay>,
  React.ComponentPropsWithoutRef<typeof SheetPrimitive.Overlay>
>(({ className, ...props }, ref) => (
  <SheetPrimitive.Overlay
    ref={ref}
    className={cn(
      // Lighter than sheet.tsx's black/80 and blurred: the page behind a
      // floating panel is deliberately still legible as context, which is the
      // whole reason for insetting it rather than covering the edge.
      "fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px]",
      "data-[state=open]:animate-in data-[state=closed]:animate-out",
      "data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0",
      className
    )}
    {...props}
  />
))
PanelSheetOverlay.displayName = "PanelSheetOverlay"

const panelSheetVariants = cva(
  [
    "fixed z-50 flex flex-col bg-background shadow-2xl",
    "transition ease-in-out",
    "data-[state=open]:animate-in data-[state=closed]:animate-out",
    "data-[state=closed]:duration-200 data-[state=open]:duration-300",
    // ── Mobile: bottom sheet, rounded top, safe height ──
    "inset-x-0 bottom-0 h-[92dvh] max-h-[92dvh] w-full rounded-t-2xl border-t",
    "data-[state=closed]:slide-out-to-bottom data-[state=open]:slide-in-from-bottom",
    // ── Desktop: floating, inset on every side, rounded all round ──
    //
    // ⚠️ `md:max-h-none` IS LOAD-BEARING, NOT TIDYING. The mobile
    // `max-h-[92dvh]` above does not stop applying at `md`, and with
    // `inset-y-4` the panel wants to be `100vh - 2rem` — which is TALLER than
    // 92dvh on any viewport over ~400px. Without this the desktop panel is
    // clamped ~8% short and floats with a visibly wrong bottom margin, so the
    // "equal margins on all sides" the design asks for silently fails on the
    // one axis nobody measures.
    "md:inset-y-4 md:left-auto md:right-4 md:h-auto md:max-h-none md:rounded-2xl md:border",
    "md:data-[state=closed]:slide-out-to-right md:data-[state=open]:slide-in-from-right",
  ].join(" "),
  {
    variants: {
      /**
       * How much of the viewport the panel claims on desktop. `wide` is the
       * default and is the ~75% the design calls for; the others exist so a
       * genuinely short form is not stretched across a monitor.
       */
      size: {
        wide: "md:w-[78vw] md:max-w-[1400px]",
        full: "md:w-[calc(100vw-2rem)] md:max-w-none",
        compact: "md:w-[52vw] md:max-w-[760px]",
      },
    },
    defaultVariants: { size: "wide" },
  }
)

interface PanelSheetContentProps
  extends React.ComponentPropsWithoutRef<typeof SheetPrimitive.Content>,
    VariantProps<typeof panelSheetVariants> {
  hideClose?: boolean
}

const PanelSheetContent = React.forwardRef<
  React.ElementRef<typeof SheetPrimitive.Content>,
  PanelSheetContentProps
>(({ size, hideClose = false, className, children, ...props }, ref) => (
  <PanelSheetPortal>
    <PanelSheetOverlay />
    <SheetPrimitive.Content
      ref={ref}
      className={cn(panelSheetVariants({ size }), className)}
      {...props}
    >
      {/* The grab handle reads as "this can be dismissed downward" on a
          phone, and is meaningless on a floating desktop panel. */}
      <div
        aria-hidden
        className="mx-auto mt-2 h-1.5 w-12 shrink-0 rounded-full bg-muted-foreground/25 md:hidden"
      />
      {children}
      {!hideClose && (
        <SheetPrimitive.Close
          className={cn(
            "absolute right-3 top-3 md:right-4 md:top-4 z-20",
            // ⚠️ 44px target. A 16px glyph is not a tap target on a phone —
            // the design system's minimum, applied to the control people
            // reach for most.
            "inline-flex h-11 w-11 lg:h-9 lg:w-9 items-center justify-center rounded-full",
            "text-muted-foreground opacity-80 transition hover:bg-muted hover:opacity-100",
            "focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
            "disabled:pointer-events-none"
          )}
        >
          <HugeiconsIcon icon={Cancel01Icon} className="h-4 w-4" />
          <span className="sr-only">Close</span>
        </SheetPrimitive.Close>
      )}
    </SheetPrimitive.Content>
  </PanelSheetPortal>
))
PanelSheetContent.displayName = "PanelSheetContent"

/** Fixed at the top of the panel — never scrolls away from the form under it. */
const PanelSheetHeader = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      "shrink-0 space-y-1.5 border-b bg-background px-4 py-4 text-left sm:px-6",
      // Clears the close button so a long title never runs under it.
      "pr-14 sm:pr-16",
      "md:rounded-t-2xl",
      className
    )}
    {...props}
  />
)
PanelSheetHeader.displayName = "PanelSheetHeader"

/**
 * The ONLY scrolling region. `min-h-0` is load-bearing: without it a flex
 * child refuses to shrink below its content and the panel grows past the
 * viewport instead of scrolling inside it.
 */
const PanelSheetBody = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      "min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 py-4 sm:px-6 sm:py-5",
      className
    )}
    {...props}
  />
)
PanelSheetBody.displayName = "PanelSheetBody"

/**
 * Fixed at the foot. Buttons stack full-width on a phone (a 44px row you can
 * hit with a thumb) and sit inline right from `sm`.
 */
const PanelSheetFooter = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) => (
  <div
    className={cn(
      "shrink-0 gap-2 border-t bg-background px-4 py-3 sm:px-6",
      "flex flex-col-reverse sm:flex-row sm:items-center sm:justify-end",
      "[&>button]:min-h-11 [&>button]:w-full sm:[&>button]:w-auto",
      // ⚠️ The home indicator sits over this row on a notched phone.
      "pb-[max(0.75rem,env(safe-area-inset-bottom))] sm:pb-3",
      "md:rounded-b-2xl",
      className
    )}
    {...props}
  />
)
PanelSheetFooter.displayName = "PanelSheetFooter"

const PanelSheetTitle = React.forwardRef<
  React.ElementRef<typeof SheetPrimitive.Title>,
  React.ComponentPropsWithoutRef<typeof SheetPrimitive.Title>
>(({ className, ...props }, ref) => (
  <SheetPrimitive.Title
    ref={ref}
    className={cn("text-base font-semibold text-foreground sm:text-lg", className)}
    {...props}
  />
))
PanelSheetTitle.displayName = "PanelSheetTitle"

const PanelSheetDescription = React.forwardRef<
  React.ElementRef<typeof SheetPrimitive.Description>,
  React.ComponentPropsWithoutRef<typeof SheetPrimitive.Description>
>(({ className, ...props }, ref) => (
  <SheetPrimitive.Description
    ref={ref}
    className={cn("text-xs text-muted-foreground sm:text-sm", className)}
    {...props}
  />
))
PanelSheetDescription.displayName = "PanelSheetDescription"

export {
  PanelSheet,
  PanelSheetPortal,
  PanelSheetOverlay,
  PanelSheetTrigger,
  PanelSheetClose,
  PanelSheetContent,
  PanelSheetHeader,
  PanelSheetBody,
  PanelSheetFooter,
  PanelSheetTitle,
  PanelSheetDescription,
}
