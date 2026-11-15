export interface PaletteItem {
  id: string;
  label: string;
  hint: string;
  group: 'Pages' | 'Boxes' | 'Actions';
}

/** Case-insensitive, every word must appear. Order is kept; an empty query keeps everything. */
export function filterItems(items: PaletteItem[], query: string): PaletteItem[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return items;
  return items.filter((i) => {
    const hay = `${i.label} ${i.hint}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}
