"use client"

// Controlled confirmation dialog — the design-system replacement for
// window.confirm (forbidden: native chrome, blocks the renderer, invisible to
// the theme). Sibling of alert-dialog rather than new props on it, per the
// UI-primitives rule.
//
// Usage: hold the pending subject in state and derive `open` from it —
//   const [payerToRemove, setPayerToRemove] = useState<Payer | null>(null)
//   <ConfirmDialog
//     open={!!payerToRemove}
//     onOpenChange={(o) => !o && setPayerToRemove(null)}
//     title="Remove payer"
//     description={`Remove "${payerToRemove?.name}" from your list?`}
//     confirmLabel="Remove"
//     destructive
//     onConfirm={() => handleRemove(payerToRemove!)}
//   />
// An async onConfirm keeps the dialog open with both buttons disabled and a
// spinner on the confirm button until it settles; if it throws, the dialog
// stays open so the caller's error toast has context.

import * as React from "react"

import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { TAP_ACTION_DEFAULT } from "@/components/ui/tap-target"

export interface ConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: React.ReactNode
  description?: React.ReactNode
  /** Label on the confirming button. Prefer a verb ("Remove", "Decline"). */
  confirmLabel?: string
  cancelLabel?: string
  /** Style the confirm button as destructive (deletes, declines). */
  destructive?: boolean
  /** May be async — the dialog shows a pending state until it settles. */
  onConfirm: () => void | Promise<void>
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive = false,
  onConfirm,
}: ConfirmDialogProps) {
  const [pending, setPending] = React.useState(false)

  const handleConfirm = async () => {
    setPending(true)
    try {
      await onConfirm()
      onOpenChange(false)
    } catch {
      // Caller surfaces its own error (toast); keep the dialog open so the
      // user still has the context to retry or cancel.
    } finally {
      setPending(false)
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={(next) => !pending && onOpenChange(next)}>
      <AlertDialogContent className="max-w-[calc(100vw-2rem)] sm:max-w-md rounded-lg">
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          {description ? (
            <AlertDialogDescription className="whitespace-pre-line">
              {description}
            </AlertDialogDescription>
          ) : null}
        </AlertDialogHeader>
        {/* gap-2 sm:gap-0 supplies the stacked-mobile spacing that
            AlertDialogCancel's own `mt-2 sm:mt-0` would have provided —
            AlertDialogFooter only spaces its children horizontally
            (sm:space-x-2). Buttons stretch full-width in the mobile column. */}
        <AlertDialogFooter className="gap-2 sm:gap-0">
          {/* Plain Buttons instead of AlertDialogAction/Cancel: those close on
              click unconditionally, which would dismiss mid-await. */}
          <Button
            type="button"
            variant="outline"
            disabled={pending}
            onClick={() => onOpenChange(false)}
            className={TAP_ACTION_DEFAULT}
          >
            {cancelLabel}
          </Button>
          <Button
            type="button"
            variant={destructive ? "destructive" : "default"}
            disabled={pending}
            onClick={handleConfirm}
            className={`gap-2 ${TAP_ACTION_DEFAULT}`}
          >
            {pending && <Spinner className="h-4 w-4" />}
            {confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
