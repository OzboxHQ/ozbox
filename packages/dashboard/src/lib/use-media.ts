import { useEffect, useState } from 'react';

/** Whether a media query matches, kept current as the window changes. */
export function useMedia(query: string): boolean {
  const [on, setOn] = useState(() => (typeof window === 'undefined' ? false : window.matchMedia(query).matches));
  useEffect(() => {
    const m = window.matchMedia(query);
    const h = () => setOn(m.matches);
    h();
    m.addEventListener('change', h);
    return () => m.removeEventListener('change', h);
  }, [query]);
  return on;
}
