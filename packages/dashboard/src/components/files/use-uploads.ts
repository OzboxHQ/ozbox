import { useCallback, useEffect, useRef, useState } from 'react';

import { ApiError } from '../../api/error';
import type { FilesApi, UploadHandle } from '../../api/files';

export type UploadState = 'queued' | 'uploading' | 'done' | 'error' | 'cancelled';

export interface UploadItem {
  id: number;
  dir: string;
  file: File;
  overwrite: boolean;
  loaded: number;
  state: UploadState;
  code?: string;
  message?: string;
}

const PARALLEL = 2;

/** A small upload queue: two at a time, each with progress, a cancel, and a retry that can replace an existing file. */
export function useUploads(api: FilesApi, box: string, onFinished: () => void) {
  const [items, setItems] = useState<UploadItem[]>([]);
  const handles = useRef(new Map<number, UploadHandle>());
  const next = useRef(1);
  const finished = useRef(onFinished);
  finished.current = onFinished;

  const patch = useCallback((id: number, p: Partial<UploadItem>) => setItems((all) => all.map((i) => (i.id === id ? { ...i, ...p } : i))), []);

  useEffect(() => {
    const running = items.filter((i) => i.state === 'uploading').length;
    const waiting = items.filter((i) => i.state === 'queued').slice(0, Math.max(0, PARALLEL - running));
    for (const item of waiting) {
      const h = api.upload(box, item.dir, item.file, {
        overwrite: item.overwrite,
        onProgress: (loaded) => patch(item.id, { loaded }),
      });
      handles.current.set(item.id, h);
      patch(item.id, { state: 'uploading', loaded: 0 });
      h.promise
        .then(() => {
          patch(item.id, { state: 'done', loaded: item.file.size });
          finished.current();
        })
        .catch((e: unknown) => {
          if (e instanceof DOMException && e.name === 'AbortError') patch(item.id, { state: 'cancelled' });
          else if (e instanceof ApiError) patch(item.id, { state: 'error', code: e.code, message: e.message });
          else patch(item.id, { state: 'error', code: 'error', message: '' });
        })
        .finally(() => handles.current.delete(item.id));
    }
  }, [items, api, box, patch]);

  const add = useCallback((dir: string, files: File[], overwrite = false) => {
    setItems((all) => [...all, ...files.map((file) => ({ id: next.current++, dir, file, overwrite, loaded: 0, state: 'queued' as UploadState }))]);
  }, []);
  const cancel = useCallback((id: number) => {
    const h = handles.current.get(id);
    if (h) h.abort();
    else patch(id, { state: 'cancelled' });
  }, [patch]);
  const retry = useCallback((id: number, overwrite: boolean) => patch(id, { state: 'queued', overwrite, loaded: 0 }), [patch]);
  const clearFinished = useCallback(() => setItems((all) => all.filter((i) => i.state === 'queued' || i.state === 'uploading')), []);
  const busy = items.some((i) => i.state === 'queued' || i.state === 'uploading');
  return { items, add, cancel, retry, clearFinished, busy };
}
