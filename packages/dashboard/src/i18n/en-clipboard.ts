/** Copy and paste: the dashboard's terminal and every Copy button. */
export const enClipboard = {
  'clipboard.secret_copied': 'It is a secret, and other apps on this computer can read your clipboard: paste it where it belongs, then copy something else.',
  'clipboard.no_gesture': 'Nothing was copied. Press Copy again.',
  'terminal.copy_title': 'Copy from the terminal',
  'terminal.copy_help': 'Nothing was selected, so here is the text on the screen. Select what you need and copy it (on a phone or tablet: press and hold, then Copy), or copy it all.',
  'terminal.copy_label': 'Text on the terminal screen',
  'terminal.copy_all': 'Copy all',
  'terminal.copy_close': 'Close',
  'terminal.osc_copied': 'Copied from the terminal',
  'terminal.osc_ask': 'A program in the terminal copied {chars} characters. Put them on your clipboard?',
  'terminal.osc_ask_action': 'Copy',
  'terminal.osc_too_large': 'A program in the terminal tried to copy {chars} characters, more than the {max} allowed at once. Nothing was copied.',
  'terminal.keys_mac': 'Cmd+C copies what you selected and Cmd+V pastes. Ctrl+C stops the running command. In tmux, drag to select: letting go copies it to your clipboard. Or hold Option while you drag, then press Cmd+C.',
  'terminal.keys_other': 'Ctrl+C copies what you selected and stops the running command when nothing is. Ctrl+V or Ctrl+Shift+V pastes. In tmux, drag to select: letting go copies it to your clipboard. Or hold Shift while you drag, then press Ctrl+C.',
  'connect.copied': 'Connect command copied',
  'connect.copy_failed': 'Could not copy. The command is: {command}',
} as const;
