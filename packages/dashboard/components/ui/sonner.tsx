"use client"

// Toast surface, the replacement for window.alert(). Mounted once at the app root and styled onto the theme tokens
// so toasts match the cards around them. Call it as `import { toast } from "sonner"`.

import { useTheme } from "next-themes"
import { Toaster as SonnerToaster } from "sonner"

export function Toaster() {
  const { resolvedTheme } = useTheme()
  return (
    <SonnerToaster
      theme={resolvedTheme === "dark" ? "dark" : "light"}
      position="bottom-right"
      closeButton
      toastOptions={{
        classNames: {
          toast: "group rounded-xl border border-border bg-card text-card-foreground shadow-lg text-sm font-medium",
          description: "text-muted-foreground",
          actionButton: "bg-primary text-primary-foreground rounded-lg font-semibold",
          cancelButton: "bg-secondary text-secondary-foreground rounded-lg font-semibold",
          error: "border-destructive/30",
          success: "border-emerald-500/40",
        },
      }}
    />
  )
}
