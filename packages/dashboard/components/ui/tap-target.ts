/**
 * Tap-target recipes.
 *
 * The responsive rule is "touch targets of at least 44x44px", and the default `size="sm"` button is `h-8` (32px):
 * a fine mouse target and a poor thumb one. The recipes live here, a sibling file in `components/ui/`, rather than
 * as new optional props on `Button`, so every surface uses the same numbers.
 *
 * THE INVERSION IS DELIBERATE: larger on small screens, not smaller. A phone or tablet is touch (820px counts as a
 * touch width), so 44px up to the desktop breakpoint; from `lg` (1024px) up the pointer is usually a mouse.
 */

/** An action button in a card, row or toolbar. 44px below `lg` (phone and tablet), 36px from `lg` up. */
export const TAP_ACTION = 'h-11 lg:h-9'

/**
 * A square icon-only control. Width is pinned too: height alone leaves a 32px wide target.
 * An icon-only control still needs an accessible name: pair this with `aria-label`, or `<span className="sr-only">`.
 */
export const TAP_ACTION_ICON = 'h-11 w-11 lg:h-9 lg:w-9'

/** A dense in-row control where several sit side by side. Same 44px floor: the density is solved by WRAPPING. */
export const TAP_ACTION_DENSE = 'h-11 px-3 lg:h-9 lg:px-3'

/** The default-size `Button` (`h-10`) in a dialog footer or form action row: 44px below `lg`, 40px from `lg` up. */
export const TAP_ACTION_DEFAULT = 'h-11 lg:h-10'

/**
 * The touch floor of a FIELD TRIGGER primitive (`SelectTrigger`). 44px minimum height below `lg`, and nothing from
 * `lg` up. `max-lg:` and not `lg:min-h-0`, because the primitives merge a caller's `className` with `cn`
 * (tailwind-merge), which only resolves conflicts between classes with the SAME modifier.
 */
export const TAP_FIELD_FLOOR = 'max-lg:min-h-11'
